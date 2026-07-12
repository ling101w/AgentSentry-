import { createHash, randomUUID } from "node:crypto";
import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const lock = JSON.parse(readFileSync(join(process.cwd(), "package-lock.json"), "utf8"));
const root = lock.packages?.[""];
if (!root?.name || !root?.version) throw new Error("package-lock.json has no root package metadata");

const components = Object.entries(lock.packages || {})
  .filter(([path, item]) => path && path.includes("node_modules/") && item && typeof item === "object" && item.version)
  .map(([path, item]) => lockComponent(path, item))
  .sort((left, right) => left["bom-ref"].localeCompare(right["bom-ref"]));

for (const [name, range] of Object.entries(root.peerDependencies || {})) {
  if (components.some((component) => component.name === name)) continue;
  components.push({
    type: "library",
    name,
    version: String(range),
    scope: "optional",
    "bom-ref": `peer:${name}@${range}`,
    properties: [{ name: "agentsentry:dependency-kind", value: "runtime-peer" }],
  });
}

const parsed = {
  bomFormat: "CycloneDX",
  specVersion: "1.5",
  serialNumber: `urn:uuid:${randomUUID()}`,
  version: 1,
  metadata: {
    timestamp: new Date().toISOString(),
    tools: {
      components: [{ type: "application", name: "agentsentry-lockfile-sbom", version: "1" }],
    },
    component: {
      type: "application",
      name: root.name,
      version: root.version,
      "bom-ref": `pkg:npm/${purlName(root.name)}@${root.version}`,
    },
  },
  components,
};
for (const component of parsed.components) {
  for (const hash of component.hashes || []) {
    if (!/^[0-9a-f]+$/i.test(hash.content) || hash.content.length % 2 !== 0) {
      throw new Error(`invalid CycloneDX hash content for ${component.name}`);
    }
  }
}
const output = join(process.cwd(), "sbom.cdx.json");
writeFileSync(output, JSON.stringify(parsed, null, 2) + "\n", "utf8");
console.log(`SBOM written to ${output} (${parsed.components.length} components)`);

function lockComponent(path, item) {
  const name = item.name || packageNameFromPath(path);
  const component = {
    type: "library",
    name,
    version: String(item.version),
    scope: item.dev ? "excluded" : item.optional ? "optional" : "required",
    "bom-ref": `lock:${createHash("sha256").update(path).digest("hex").slice(0, 20)}`,
    purl: `pkg:npm/${purlName(name)}@${encodeURIComponent(String(item.version))}`,
  };
  if (typeof item.integrity === "string" && item.integrity.includes("-")) {
    const [algorithm, content] = item.integrity.split("-", 2);
    const decoded = Buffer.from(content, "base64");
    if (decoded.length) {
      component.hashes = [{
        alg: algorithm.toUpperCase().replace(/^SHA(?=\d)/, "SHA-"),
        content: decoded.toString("hex"),
      }];
    }
  }
  if (typeof item.license === "string") component.licenses = [{ license: { id: item.license } }];
  return component;
}

function packageNameFromPath(path) {
  const parts = path.split("node_modules/").pop().split("/");
  return parts[0].startsWith("@") ? `${parts[0]}/${parts[1]}` : parts[0];
}

function purlName(name) {
  return name.startsWith("@") ? `${encodeURIComponent(name.split("/")[0])}/${encodeURIComponent(name.split("/")[1])}` : encodeURIComponent(name);
}
