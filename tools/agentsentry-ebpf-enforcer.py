#!/usr/bin/env python3
"""Optional kernel network gate for AgentSentry sandbox processes.

This service is deliberately fail-closed at startup: it exits when cgroup BPF
connect enforcement is unavailable. The OpenClaw plugin
must continue to use its application preflight and workspace rollback layers;
this process is a last-mile network boundary for registered sandbox PIDs.

The control socket accepts only local JSON commands:
  {"op":"register","pid":1234,"deny_network":true}
  {"op":"unregister","pid":1234}
  {"op":"status"}

Each registered PID is moved into a dedicated cgroup. IPv4 and IPv6 connections
are denied for that cgroup unless the destination is loopback. This prevents a
short-lived sandbox from changing the network policy of the whole gateway
service cgroup.
"""

from __future__ import annotations

import argparse
import json
import os
import signal
import socket
import stat
import sys
import time
import shutil
import struct
from pathlib import Path
from threading import Thread

try:
    from bcc import BPF
except ImportError as exc:  # pragma: no cover - exercised by deployment check
    BPF = None  # type: ignore[assignment]
    BCC_IMPORT_ERROR = str(exc)
else:
    BCC_IMPORT_ERROR = ""


BPF_PROGRAM = r"""
#include <uapi/linux/ptrace.h>
#include <linux/bpf.h>
int enforce_egress(struct __sk_buff *skb) {
  /* cgroup_skb exposes the IP packet, so inspect the IP version nibble. */
  u8 first_byte = 0;
  bpf_skb_load_bytes(skb, 0, &first_byte, sizeof(first_byte));
  if ((first_byte >> 4) == 4) {
    u32 destination = 0;
    bpf_skb_load_bytes(skb, 16, &destination, sizeof(destination));
    /* IPv4 loopback remains available for the local control plane. */
    if ((destination & 0x000000ff) == 0x0000007f) return 1;
  } else if ((first_byte >> 4) == 6) {
    u8 destination[16] = {};
    bpf_skb_load_bytes(skb, 24, destination, sizeof(destination));
    if (destination[15] == 1) {
      int loopback = 1;
      #pragma unroll
      for (int i = 0; i < 15; i++) loopback &= destination[i] == 0;
      if (loopback) return 1;
    }
  }
  return 0;
}
"""


def kernel_lsm_enabled() -> bool:
    try:
        return "bpf" in Path("/sys/kernel/security/lsm").read_text().split(",")
    except OSError:
        return False


def capability_report() -> dict[str, object]:
    return {
        "bpf_lsm": kernel_lsm_enabled(),
        "cgroup_bpf": Path("/sys/fs/cgroup/cgroup.controllers").exists(),
        "bcc": BPF is not None,
        "uid": os.geteuid(),
        "supported": bool(Path("/sys/fs/cgroup/cgroup.controllers").exists() and BPF is not None and os.geteuid() == 0),
        "reason": "" if Path("/sys/fs/cgroup/cgroup.controllers").exists() and BPF is not None and os.geteuid() == 0 else "cgroup BPF, BCC and root privileges are required",
    }


class Enforcer:
    def __init__(self, log_path: Path):
        report = capability_report()
        if not report["supported"]:
            raise RuntimeError(json.dumps(report, ensure_ascii=False))
        self.log_path = log_path
        self.log_path.parent.mkdir(parents=True, exist_ok=True)
        self.bpf = BPF(text=BPF_PROGRAM)
        self.cgroup_root = Path("/sys/fs/cgroup/agentsentry-sandbox")
        self.cgroup_root.mkdir(parents=True, exist_ok=True)
        self.attachments: dict[str, tuple[int, object, Path, Path]] = {}
        self.pid_to_cgroup: dict[int, str] = {}
        self.registered: set[int] = set()
        self.running = True

    def _write(self, value: dict[str, object]) -> None:
        with self.log_path.open("a", encoding="utf-8") as stream:
            stream.write(json.dumps({"ts": time.time(), **value}, ensure_ascii=False) + "\n")

    def register(self, pid: int, deny_network: bool) -> None:
        if deny_network:
            self._attach_cgroup_for_pid(pid)
        else:
            self._detach_cgroup_for_pid(pid)
        if deny_network:
            self.registered.add(pid)
        else:
            self.registered.discard(pid)
        self._write({"event": "policy_register", "pid": pid, "deny_network": deny_network})

    def unregister(self, pid: int) -> None:
        self._detach_cgroup_for_pid(pid)
        self.registered.discard(pid)
        self._write({"event": "policy_unregister", "pid": pid})

    def _cgroup_path_for_pid(self, pid: int) -> Path:
        for line in Path(f"/proc/{pid}/cgroup").read_text().splitlines():
            hierarchy, _, relative = line.partition(":")
            if hierarchy == "0":
                _, _, relative = relative.partition(":")
                return Path("/sys/fs/cgroup") / relative.lstrip("/")
        raise RuntimeError(f"pid {pid} is not in a cgroup v2 hierarchy")

    def _attach_cgroup_for_pid(self, pid: int) -> None:
        original_path = self._cgroup_path_for_pid(pid)
        sandbox_path = self.cgroup_root / str(pid)
        key = str(sandbox_path)
        if key in self.attachments:
            return
        sandbox_path.mkdir(exist_ok=True)
        (sandbox_path / "cgroup.procs").write_text(str(pid), encoding="ascii")
        fd: int | None = None
        try:
            fd = os.open(sandbox_path, os.O_RDONLY | os.O_DIRECTORY)
            fn = self.bpf.load_func("enforce_egress", BPF.CGROUP_SKB)
            BPF.attach_func(fn, fd, 1)
        except Exception:
            try:
                (original_path / "cgroup.procs").write_text(str(pid), encoding="ascii")
            except OSError:
                pass
            try:
                sandbox_path.rmdir()
            except OSError:
                pass
            if fd is not None:
                os.close(fd)
            raise
        assert fd is not None
        self.attachments[key] = (fd, fn, sandbox_path, original_path)
        self.pid_to_cgroup[pid] = key
        self._write({"event": "cgroup_enforcement_attached", "pid": pid, "cgroup": key, "original_cgroup": str(original_path)})

    def _detach_cgroup_for_pid(self, pid: int) -> None:
        key = self.pid_to_cgroup.get(pid)
        if key is None:
            return
        attachment = self.attachments.pop(key, None)
        if not attachment:
            return
        fd, fn, sandbox_path, original_path = attachment
        try:
            pids = [value for value in (sandbox_path / "cgroup.procs").read_text(encoding="ascii").split()]
            for value in pids:
                (original_path / "cgroup.procs").write_text(value, encoding="ascii")
        except OSError:
            pass
        try:
            BPF.detach_func(fn, fd, 1)
        except Exception:
            pass
        os.close(fd)
        try:
            sandbox_path.rmdir()
        except OSError:
            pass
        self.pid_to_cgroup.pop(pid, None)
        self._write({"event": "cgroup_enforcement_detached", "pid": pid, "cgroup": key})

    def poll(self) -> None:
        for pid, key in list(self.pid_to_cgroup.items()):
            if not Path(f"/proc/{pid}").exists():
                attachment = self.attachments.pop(key, None)
                if not attachment:
                    self.pid_to_cgroup.pop(pid, None)
                    continue
                fd, fn, sandbox_path, _original_path = attachment
                try:
                    BPF.detach_func(fn, fd, 1)
                except Exception:
                    pass
                os.close(fd)
                try:
                    sandbox_path.rmdir()
                except OSError:
                    pass
                self.pid_to_cgroup.pop(pid, None)
                self._write({"event": "cgroup_enforcement_reaped", "pid": pid, "cgroup": key})
        time.sleep(0.01)

    def close(self) -> None:
        self.running = False
        for key, (fd, fn, sandbox_path, original_path) in list(self.attachments.items()):
            try:
                pids = [int(value) for value in (sandbox_path / "cgroup.procs").read_text(encoding="ascii").split()]
                for pid in pids:
                    (original_path / "cgroup.procs").write_text(str(pid), encoding="ascii")
            except OSError:
                pass
            try:
                BPF.detach_func(fn, fd, 1)
            except Exception:
                pass
            os.close(fd)
            self._write({"event": "cgroup_enforcement_detached", "cgroup": key})
        self.attachments.clear()
        self.pid_to_cgroup.clear()
        self.bpf.cleanup()
        try:
            self.cgroup_root.rmdir()
        except OSError:
            pass


def peer_credentials(connection: socket.socket) -> tuple[int, int]:
    # Linux returns pid, uid and gid as three native-endian int32 values.
    peer_pid, peer_uid, _peer_gid = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
    return peer_pid, peer_uid


def authorize_target_pid(connection: socket.socket, target_pid: int) -> None:
    _peer_pid, peer_uid = peer_credentials(connection)
    target_uid = os.stat(f"/proc/{target_pid}").st_uid
    if peer_uid != 0 and target_uid != peer_uid:
        raise PermissionError("control client may only register processes owned by its uid")


def handle_connection(connection: socket.socket, enforcer: Enforcer) -> None:
    try:
        request = json.loads(connection.recv(65536).decode("utf-8"))
        operation = request.get("op")
        if operation == "register":
            pid = int(request["pid"])
            authorize_target_pid(connection, pid)
            enforcer.register(pid, bool(request.get("deny_network", True)))
            response = {"ok": True, "enforced": True}
        elif operation == "unregister":
            pid = int(request["pid"])
            authorize_target_pid(connection, pid)
            enforcer.unregister(pid)
            response = {"ok": True}
        elif operation == "status":
            response = {"ok": True, "capability": capability_report(), "registered": sorted(enforcer.registered)}
        else:
            response = {"ok": False, "error": "unknown operation"}
    except Exception as exc:  # the client receives a structured failure
        response = {"ok": False, "error": str(exc)}
    connection.sendall((json.dumps(response, ensure_ascii=False) + "\n").encode("utf-8"))
    connection.close()


def serve(socket_path: Path, log_path: Path, socket_group: str) -> int:
    enforcer = Enforcer(log_path)
    socket_path.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(socket_path.parent, stat.S_IRWXU | stat.S_IRGRP | stat.S_IXGRP)
    shutil.chown(socket_path.parent, group=socket_group)
    try:
        socket_path.unlink()
    except FileNotFoundError:
        pass
    server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    server.bind(str(socket_path))
    os.chmod(socket_path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IRGRP | stat.S_IWGRP)
    shutil.chown(socket_path, group=socket_group)
    server.listen(16)
    signal.signal(signal.SIGTERM, lambda _signum, _frame: setattr(enforcer, "running", False))
    signal.signal(signal.SIGINT, lambda _signum, _frame: setattr(enforcer, "running", False))
    try:
        while enforcer.running:
            server.settimeout(0.1)
            try:
                connection, _ = server.accept()
            except socket.timeout:
                enforcer.poll()
                continue
            Thread(target=handle_connection, args=(connection, enforcer), daemon=True).start()
            enforcer.poll()
    finally:
        enforcer.close()
        server.close()
        try:
            socket_path.unlink()
        except FileNotFoundError:
            pass
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description="AgentSentry kernel network enforcement service")
    parser.add_argument("--check", action="store_true")
    parser.add_argument("--socket", type=Path, default=Path("/run/agentsentry/ebpf-enforcer.sock"))
    parser.add_argument("--log", type=Path, default=Path("/var/log/agentsentry-ebpf-enforcer.jsonl"))
    parser.add_argument("--socket-group", default="ubuntu")
    args = parser.parse_args()
    if args.check:
        print(json.dumps(capability_report(), ensure_ascii=False))
        return 0 if capability_report()["supported"] else 2
    try:
        return serve(args.socket, args.log, args.socket_group)
    except Exception as exc:
        print(str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
