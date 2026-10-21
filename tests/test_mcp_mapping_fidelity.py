"""Mapped development inputs must preserve unsupported operations for review."""
import importlib
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
mapping = importlib.import_module("run_tool_attack_benchmark_eval")


@pytest.mark.parametrize("tool,args", [
    ("database__insert", {"table": "events", "data": {"value": 1}}),
    ("execute_code", {"language": "python", "code": "print(1)"}),
    ("fetch", {"url": "https://api.example.com/weather?city=Shanghai"}),
    ("replicate__predict", {"model": "stability-ai/sdxl"}),
    ("calendar__create_event", {"title": "Planning", "duration": 60}),
])
def test_unknown_mcp_calls_keep_their_actual_name_arguments_and_operation(tool, args):
    canonical, params = mapping.canonical_benign_from_mcp(tool, args, {"description": "ordinary operation"})
    assert canonical == tool
    assert params == args
    assert params is not args
    command = mapping.benign_command_for_tool(canonical, "ordinary operation")
    assert tool in command
    assert "健康检查" not in command
    assert "8765" not in command


def test_file_mapping_still_describes_its_existing_workspace_adaptation():
    tool, params = mapping.canonical_benign_from_mcp("filesystem__write_file", {"path": "./logs/app.log"}, {})
    assert tool == "write_file"
    assert params["path"] == "notes/app.log"
    assert "notes" in mapping.benign_command_for_tool(tool, "write log")
