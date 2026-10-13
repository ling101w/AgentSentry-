import { createServer, type Server, type RequestListener } from "node:http";
import { lookup } from "node:dns/promises";
import { afterEach, describe, expect, it, vi } from "vitest";
import { isAddressAuthorized, safeHttpGet, safeHttpPost } from "../../core/ssrf-http.ts";

vi.mock("node:dns/promises", async (importOriginal) => ({
  ...await importOriginal<typeof import("node:dns/promises")>(), lookup: vi.fn(),
}));
const servers: Server[] = [];
afterEach(async () => {
  await Promise.all(servers.splice(0).map((server) => new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))));
  vi.resetAllMocks();
});
async function endpoint(handler: RequestListener): Promise<string> {
  const server = createServer(handler);
  servers.push(server);
  await new Promise<void>((resolve) => server.listen(0, "127.0.0.1", resolve));
  const address = server.address();
  if (!address || typeof address === "string") throw new Error("fixture has no port");
  return `http://127.0.0.1:${address.port}`;
}

describe("separate HTTP target and address permissions", () => {
  it("rejects an allowlisted domain resolving to loopback for GET and POST", async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: "127.0.0.1", family: 4 }] as never);
    const options = { allowedHosts: ["internal.test"] };
    await expect(safeHttpGet("http://internal.test/", options)).rejects.toThrow(/SSRF protection/);
    await expect(safeHttpPost("http://internal.test/", {}, options)).rejects.toThrow(/SSRF protection/);
  });
  it("rejects mixed DNS answers when any address is unauthorized", async () => {
    vi.mocked(lookup).mockResolvedValue([{ address: "8.8.8.8", family: 4 }, { address: "10.1.2.3", family: 4 }] as never);
    await expect(safeHttpGet("http://internal.test/", { allowedHosts: ["internal.test"] })).rejects.toThrow(/SSRF protection/);
  });
  it("authorizes only matching private CIDRs without unlocking reserved ranges", () => {
    const url = new URL("https://internal.test/");
    const options = { allowedPrivateCidrs: ["10.1.0.0/16", "fd00::/8"] };
    expect(isAddressAuthorized("10.1.2.3", url, options)).toBe(true);
    expect(isAddressAuthorized("10.2.2.3", url, options)).toBe(false);
    expect(isAddressAuthorized("fd12::1", url, options)).toBe(true);
    expect(isAddressAuthorized("fc12::1", url, options)).toBe(false);
    for (const address of ["127.0.0.1", "::1", "169.254.169.254", "169.254.170.2", "100.100.100.200", "168.63.129.16", "fd00:ec2::254", "0.0.0.0", "fe80::1", "::ffff:127.0.0.1"]) {
      expect(isAddressAuthorized(address, url, { allowedPrivateCidrs: ["0.0.0.0/0", "::/0"], allowedHosts: ["internal.test"] })).toBe(false);
    }
    expect(isAddressAuthorized("10.1.2.3", url, { allowedPrivateCidrs: ["invalid", "10.0.0.0/999", "10.0.0.0/8/extra"] })).toBe(false);
  });
  it("pins connections and requires an explicit loopback origin", async () => {
    const origin = await endpoint((request, response) => response.end(`${request.method}:${request.headers.host}`));
    const url = origin.replace("127.0.0.1", "internal.test");
    vi.mocked(lookup).mockResolvedValue([{ address: "127.0.0.1", family: 4 }] as never);
    const options = { allowedHosts: ["internal.test"], allowedLoopbackOrigins: [url] };
    expect((await safeHttpGet(url, options)).body).toBe(`GET:${new URL(url).host}`);
    expect((await safeHttpPost(url, {}, options)).status).toBe(200);
    expect(lookup).toHaveBeenCalledTimes(2);
  });
  it("revalidates address permission on every redirect including a changed port", async () => {
    const final = await endpoint((_request, response) => response.end("final"));
    const initial = await endpoint((_request, response) => {
      response.writeHead(302, { Location: final }); response.end();
    });
    await expect(safeHttpGet(initial, { allowedHosts: ["127.0.0.1"], allowedLoopbackOrigins: [initial] })).rejects.toThrow(/SSRF protection/);
    expect(await safeHttpGet(initial, { allowedHosts: ["127.0.0.1"], allowedLoopbackOrigins: [initial, final] })).toMatchObject({ body: "final", redirects: 1 });
  });
  it("rejects redirected hosts outside the host allowlist", async () => {
    const initial = await endpoint((_request, response) => {
      response.writeHead(302, { Location: "http://other.test/" }); response.end();
    });
    await expect(safeHttpGet(initial, { allowedHosts: ["127.0.0.1"], allowedLoopbackOrigins: [initial] })).rejects.toThrow(/not allowlisted/);
    expect(lookup).not.toHaveBeenCalled();
  });
});
