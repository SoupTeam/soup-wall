// SPDX-License-Identifier: Apache-2.0
// Trusted, source-embedded bootstrap for the pinned compiled Bun host only.
'use strict';
(() => {
  const fs = require('node:fs');
  const keys = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'SSL_CERT_FILE'];
  const internal = ['BUN_OPTIONS', 'NODE_OPTIONS', 'AGENTFW_PROVIDER_CHANNEL', 'AGENTFW_PROVIDER_CODE'];
  const blocked = new Set([...keys, ...internal]);
  const clean = env => Object.fromEntries(Object.entries(env ?? process.env)
    .filter(([key]) => !blocked.has(key)));
  const options = (args, index) => {
    const supplied = args[index];
    const value = { ...(supplied && typeof supplied === 'object' ? supplied : {}),
      env: clean(supplied?.env) };
    if (typeof supplied === 'function') args.splice(index, 0, value);
    else args[index] = value;
    return args;
  };
  const cp = require('node:child_process');
  // The prototype is a final guard for Node async APIs, including cached exports.
  const originalSpawn = cp.ChildProcess.prototype.spawn;
  cp.ChildProcess.prototype.spawn = function (value) {
    return originalSpawn.call(this, { ...value, envPairs: (value.envPairs ??
      Object.entries(process.env).map(([k, v]) => k + '=' + v))
      .filter(pair => !blocked.has(pair.slice(0, pair.indexOf('=')))) });
  };
  for (const name of ['spawn', 'spawnSync', 'execFile', 'execFileSync', 'fork', 'exec', 'execSync']) {
    const original = cp[name];
    if (typeof original !== 'function') throw Error('provider_bootstrap_unavailable');
    cp[name] = function (...args) {
      const index = name === 'exec' || name === 'execSync' ? 1 : Array.isArray(args[1]) ? 2 : 1;
      return original.apply(this, options(args, index));
    };
  }
  require('node:module').syncBuiltinESMExports();
  for (const name of ['spawn', 'spawnSync']) {
    const original = Bun[name];
    if (typeof original !== 'function') throw Error('provider_bootstrap_unavailable');
    Bun[name] = function (cmd, opts) {
      return Array.isArray(cmd) ? original.call(this, cmd, { ...opts, env: clean(opts?.env) }) :
        original.call(this, { ...cmd, env: clean(cmd?.env) });
    };
  }
  // The fixed host uses child_process for its reviewed helpers. A native shell
  // path has no reviewed credential boundary and must not become a fallback.
  Object.defineProperty(Bun, '$', { value() { throw Error('provider_shell_unsupported'); },
    writable: false, configurable: false });

  const channel = Number(process.env.AGENTFW_PROVIDER_CHANNEL);
  const code = Number(process.env.AGENTFW_PROVIDER_CODE);
  if (!Number.isSafeInteger(channel) || channel < 3 || !Number.isSafeInteger(code) || code < 3
      || channel === code) throw Error('provider_bootstrap_unavailable');
  fs.closeSync(code);
  const { dlopen, FFIType, ptr } = require('bun:ffi');
  const libc = dlopen('libc.so.6', {
    send: { args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32], returns: FFIType.i64 },
    recv: { args: [FFIType.i32, FFIType.ptr, FFIType.u64, FFIType.i32], returns: FFIType.i64 }
  });
  const hello = Buffer.from('sw-provider-ready/1');
  let raw;
  try {
    if (Number(libc.symbols.send(channel, ptr(hello), hello.length, 0)) !== hello.length)
      throw Error('provider_bootstrap_unavailable');
    const data = Buffer.alloc(16385);
    const length = Number(libc.symbols.recv(channel, ptr(data), data.length, 0));
    if (length < 2 || length > 16384) throw Error('provider_bootstrap_unavailable');
    raw = JSON.parse(new TextDecoder('utf-8', { fatal: true }).decode(data.subarray(0, length)));
    data.fill(0);
  } finally {
    fs.closeSync(channel);
    libc.close();
    for (const key of internal) delete process.env[key];
  }
  if (raw === null || Array.isArray(raw) || typeof raw !== 'object'
      || Object.entries(raw).some(([k, v]) => !keys.includes(k) || typeof v !== 'string' || v.includes('\0')))
    throw Error('provider_bootstrap_unavailable');
  for (const key of keys) delete process.env[key];
  for (const [key, value] of Object.entries(raw)) process.env[key] = value;
})();
