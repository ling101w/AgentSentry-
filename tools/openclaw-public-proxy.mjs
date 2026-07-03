import crypto from 'node:crypto';
import fs from 'node:fs';
import http from 'node:http';
import net from 'node:net';
import os from 'node:os';
import zlib from 'node:zlib';

const listenPort = Number.parseInt(process.env.PUBLIC_PROXY_PORT || '18789', 10);
const targetHost = process.env.PUBLIC_PROXY_TARGET_HOST || '127.0.0.1';
const targetPort = Number.parseInt(process.env.PUBLIC_PROXY_TARGET_PORT || '18789', 10);
const authUser = process.env.PUBLIC_PROXY_USER || 'admin';
const authSha256 = process.env.PUBLIC_PROXY_AUTH_SHA256;
const gatewayConfigPath = process.env.PUBLIC_PROXY_GATEWAY_CONFIG || '/home/ubuntu/.openclaw/openclaw.json';

if (!authSha256) {
  console.error('PUBLIC_PROXY_AUTH_SHA256 is required');
  process.exit(78);
}

function pickBindHost() {
  if (process.env.PUBLIC_PROXY_BIND_HOST) {
    return process.env.PUBLIC_PROXY_BIND_HOST;
  }

  for (const entries of Object.values(os.networkInterfaces())) {
    for (const entry of entries || []) {
      if (entry.family === 'IPv4' && !entry.internal) {
        return entry.address;
      }
    }
  }

  return '0.0.0.0';
}

const bindHost = pickBindHost();

function gatewayToken() {
  const direct = process.env.PUBLIC_PROXY_GATEWAY_TOKEN?.trim();
  if (direct) {
    return direct;
  }

  try {
    const raw = fs.readFileSync(gatewayConfigPath, 'utf8');
    const config = JSON.parse(raw);
    const token = config?.gateway?.auth?.token;
    return typeof token === 'string' && token.trim() ? token.trim() : null;
  } catch (error) {
    console.error('failed to read OpenClaw gateway token:', error.message);
    return null;
  }
}

function unauthorized(socketOrResponse) {
  const headers = [
    'HTTP/1.1 401 Unauthorized',
    'WWW-Authenticate: Basic realm="OpenClaw Control"',
    'Content-Type: text/plain; charset=utf-8',
    'Connection: close',
    '',
    'Authentication required',
  ].join('\r\n');

  if ('writeHead' in socketOrResponse) {
    socketOrResponse.writeHead(401, {
      'WWW-Authenticate': 'Basic realm="OpenClaw Control"',
      'Content-Type': 'text/plain; charset=utf-8',
    });
    socketOrResponse.end('Authentication required');
    return;
  }

  socketOrResponse.write(headers);
  socketOrResponse.destroy();
}

function isAuthorized(header) {
  if (!header) {
    return false;
  }

  if (header.startsWith('Bearer ')) {
    const supplied = header.slice(7).trim();
    const token = gatewayToken();
    if (!supplied || !token) {
      return false;
    }

    const suppliedBuffer = Buffer.from(supplied);
    const expectedBuffer = Buffer.from(token);
    return suppliedBuffer.length === expectedBuffer.length && crypto.timingSafeEqual(suppliedBuffer, expectedBuffer);
  }

  if (!header.startsWith('Basic ')) {
    return false;
  }

  let decoded;
  try {
    decoded = Buffer.from(header.slice(6), 'base64').toString('utf8');
  } catch {
    return false;
  }

  const digest = crypto.createHash('sha256').update(decoded).digest('hex');
  const digestBuffer = Buffer.from(digest, 'hex');
  const expectedBuffer = Buffer.from(authSha256, 'hex');
  if (digestBuffer.length !== expectedBuffer.length) {
    return false;
  }

  return decoded.startsWith(`${authUser}:`) && crypto.timingSafeEqual(digestBuffer, expectedBuffer);
}

function hasBootstrapCookie(header) {
  return String(header || '')
    .split(';')
    .map((part) => part.trim())
    .includes('openclaw_public_auth=1');
}

function redirectWithToken(req, res, token) {
  const host = req.headers.host || `127.0.0.1:${listenPort}`;
  const next = new URL(req.url || '/', `http://${host}`);
  next.hash = new URLSearchParams({ token }).toString();
  res.writeHead(302, {
    Location: `${next.pathname}${next.search}${next.hash}`,
    'Set-Cookie': 'openclaw_public_auth=1; Path=/; HttpOnly; SameSite=Lax; Max-Age=3600',
    'Cache-Control': 'no-store',
  });
  res.end();
}

function stripHopByHopHeaders(headers) {
  const next = { ...headers };
  for (const key of [
    'authorization',
    'connection',
    'keep-alive',
    'proxy-authenticate',
    'proxy-authorization',
    'te',
    'trailer',
    'transfer-encoding',
    'upgrade',
  ]) {
    delete next[key];
  }
  return next;
}

function isHashedAssetPath(path = '') {
  return /^\/?assets\/.+-[A-Za-z0-9_-]{6,}\.(?:js|css|mjs|woff2?|png|jpg|jpeg|svg|webp)$/i.test(path.split('?')[0] || '');
}

function isCompressibleContentType(contentType = '') {
  return /(?:text\/|javascript|json|xml|svg|wasm)/i.test(contentType);
}

function clientAcceptsGzip(req) {
  return /\bgzip\b/i.test(String(req.headers['accept-encoding'] || ''));
}

function normalizedProxyHeaders(proxyRes, req) {
  const headers = { ...proxyRes.headers };
  const requestPath = req.url || '/';
  const contentType = String(headers['content-type'] || '');
  const canGzip = clientAcceptsGzip(req)
    && isCompressibleContentType(contentType)
    && !headers['content-encoding']
    && req.method !== 'HEAD';

  if (canGzip) {
    headers['content-encoding'] = 'gzip';
    headers.vary = headers.vary ? `${headers.vary}, Accept-Encoding` : 'Accept-Encoding';
    delete headers['content-length'];
  }

  if (isHashedAssetPath(requestPath)) {
    headers['cache-control'] = 'public, max-age=31536000, immutable';
  } else if (/^\/?(?:favicon|manifest|apple-touch-icon)/i.test(requestPath)) {
    headers['cache-control'] = 'public, max-age=86400';
  }

  if (typeof headers['content-security-policy'] === 'string') {
    headers['content-security-policy'] = headers['content-security-policy']
      .replace(/\shttps:\/\/fonts\.googleapis\.com/g, '')
      .replace(/\shttps:\/\/fonts\.gstatic\.com/g, '');
  }

  return { headers, canGzip };
}

const server = http.createServer((req, res) => {
  if (!isAuthorized(req.headers.authorization)) {
    unauthorized(res);
    return;
  }

  const token = gatewayToken();
  const wantsHtml = String(req.headers.accept || '').includes('text/html');
  if (req.method === 'GET' && wantsHtml && token && !hasBootstrapCookie(req.headers.cookie)) {
    redirectWithToken(req, res, token);
    return;
  }

  const proxyReq = http.request(
    {
      host: targetHost,
      port: targetPort,
      method: req.method,
      path: req.url,
      headers: {
        ...stripHopByHopHeaders(req.headers),
        host: `${targetHost}:${targetPort}`,
        authorization: req.headers.authorization?.startsWith('Bearer ')
          ? req.headers.authorization
          : token
            ? `Bearer ${token}`
            : '',
        'x-forwarded-host': req.headers.host || '',
        'x-forwarded-proto': 'http',
        'x-forwarded-for': req.socket.remoteAddress || '',
        'x-forwarded-user': authUser,
      },
    },
    (proxyRes) => {
      const { headers, canGzip } = normalizedProxyHeaders(proxyRes, req);
      res.writeHead(proxyRes.statusCode || 502, headers);
      if (canGzip) {
        proxyRes.pipe(zlib.createGzip()).pipe(res);
        return;
      }
      proxyRes.pipe(res);
    },
  );

  proxyReq.on('error', (error) => {
    console.error('proxy request failed:', error.message);
    if (!res.headersSent) {
      res.writeHead(502, { 'Content-Type': 'text/plain; charset=utf-8' });
    }
    res.end('OpenClaw backend unavailable');
  });

  req.pipe(proxyReq);
});

server.on('upgrade', (req, socket, head) => {
  if (!isAuthorized(req.headers.authorization)) {
    unauthorized(socket);
    return;
  }

  const upstream = net.connect(targetPort, targetHost, () => {
    const headers = {
      ...req.headers,
      host: `${targetHost}:${targetPort}`,
      connection: 'Upgrade',
      upgrade: req.headers.upgrade || 'websocket',
      'x-forwarded-host': req.headers.host || '',
      'x-forwarded-proto': 'http',
      'x-forwarded-for': req.socket.remoteAddress || '',
      'x-forwarded-user': authUser,
    };
    delete headers.authorization;
    delete headers['proxy-authorization'];

    upstream.write(
      [
        `${req.method} ${req.url} HTTP/${req.httpVersion}`,
        ...Object.entries(headers)
          .map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`),
        '',
        '',
      ].join('\r\n'),
    );
    if (head?.length) {
      upstream.write(head);
    }
    upstream.pipe(socket);
    socket.pipe(upstream);
  });

  upstream.on('error', (error) => {
    console.error('proxy upgrade failed:', error.message);
    socket.destroy();
  });
});

server.on('error', (error) => {
  console.error(`OpenClaw public proxy failed on ${bindHost}:${listenPort}:`, error.message);
  process.exit(1);
});

server.listen(listenPort, bindHost, () => {
  console.log(`OpenClaw public proxy listening on ${bindHost}:${listenPort}, target ${targetHost}:${targetPort}`);
});
