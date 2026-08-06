import { chmodSync, mkdirSync, readFileSync, writeFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import type { PluginConfig } from "../config.ts";

export function agentSentryStateDir(config: PluginConfig): string {
  const stateDir = config.storage.stateDir || process.env.OPENCLAW_STATE_DIR?.trim() || join(homedir(), ".openclaw");
  return join(stateDir, "agentsentry");
}

export function stateSecretPath(config: PluginConfig, name: string): string {
  if (!/^[a-z0-9][a-z0-9-]*$/i.test(name)) throw new Error(`invalid state secret name: ${name}`);
  return join(agentSentryStateDir(config), `${name}.key`);
}

export function loadOrCreateStateSecret(config: PluginConfig, name: string): Buffer {
  const path = stateSecretPath(config, name);
  mkdirSync(dirname(path), { recursive: true });

  try {
    return readSecret(path);
  } catch (error) {
    if (!isMissingPathError(error)) throw error;
  }

  const generated = randomBytes(32);
  try {
    writeFileSync(path, `${generated.toString("base64url")}\n`, { encoding: "utf8", flag: "wx", mode: 0o600 });
  } catch (error) {
    if (!isAlreadyExistsError(error)) throw error;
    return readSecret(path);
  }
  chmodOwnerOnly(path);
  return generated;
}

function readSecret(path: string): Buffer {
  const encoded = readFileSync(path, "utf8").trim();
  if (!/^[A-Za-z0-9_-]{43}$/.test(encoded)) throw new Error(`invalid AgentSentry secret file: ${path}`);
  const secret = Buffer.from(encoded, "base64url");
  if (secret.length !== 32) throw new Error(`invalid AgentSentry secret length: ${path}`);
  chmodOwnerOnly(path);
  return secret;
}

function chmodOwnerOnly(path: string): void {
  try {
    chmodSync(path, 0o600);
  } catch (error) {
    if (process.platform !== "win32") throw error;
  }
}

function isMissingPathError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: string }).code === "ENOENT");
}

function isAlreadyExistsError(error: unknown): boolean {
  return Boolean(error && typeof error === "object" && "code" in error && (error as { code?: string }).code === "EEXIST");
}
