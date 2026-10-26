// SPDX-License-Identifier: Apache-2.0
// Trusted, source-embedded bootstrap for the pinned compiled Bun host only.
'use strict';
let stage = 'hooks';
try { (() => {
  const fs = require('node:fs');
  const keys = ['ANTHROPIC_API_KEY', 'ANTHROPIC_AUTH_TOKEN', 'ANTHROPIC_BASE_URL',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'SSL_CERT_FILE'];
  const internal = ['BUN_OPTIONS', 'NODE_OPTIONS', 'AGENTFW_PROVIDER_READY_FD'];
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

  stage = 'ready';
  const channel = Number(process.env.AGENTFW_PROVIDER_READY_FD);
  if (!Number.isSafeInteger(channel) || channel < 3) throw Error('provider_child_environment_unavailable');
  const ready = Buffer.from('sw-provider-ready/1');
  try {
    if (fs.writeSync(channel, ready) !== ready.length) throw Error('provider_child_environment_unavailable');
  } finally {
    fs.closeSync(channel);
    for (const key of internal) delete process.env[key];
  }
})(); } catch {
  try { require('node:fs').writeSync(2, 'sw-provider-scrub-failed/' + stage + '\n'); }
  finally { process.exit(78); }
}
