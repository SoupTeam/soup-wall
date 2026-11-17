// SPDX-License-Identifier: Apache-2.0
// Qualified against opencode-ai 1.19.6's tool.execute.before/after plugin API.
import { spawnSync } from "node:child_process";
import { isAbsolute } from "node:path";

export const SoupWall = async ({ directory }) => {
  // These are operator launch settings. Native identity comes from the private
  // signed binding, never from the sessionID/callID supplied by the host.
  const binary = process.env.SOUP_WALL_AGENTFW;
  const home = process.env.SOUP_WALL_HOME;
  const binding = process.env.SOUP_WALL_BINDING;
  const decide = (phase, input, output) => {
    if (![binary, home, binding].every((x) => typeof x === "string" && isAbsolute(x)))
      throw new Error("Soup Wall plugin is missing its private launch binding.");
    const frame = JSON.stringify({ phase, input, output, cwd: directory });
    if (Buffer.byteLength(frame) > 1024 * 1024)
      throw new Error("Soup Wall cannot inspect the complete callback.");
    const result = spawnSync(binary, ["opencode-hook", "--home", home, "--binding", binding], {
      input: frame, encoding: "utf8", timeout: 2500, maxBuffer: 65536,
      env: { PATH: "/usr/bin:/bin" }, windowsHide: true,
    });
    if (result.error || result.status !== 0)
      throw new Error("Soup Wall callback is unavailable; the call/result is withheld.");
    let receipt;
    try { receipt = JSON.parse(result.stdout); }
    catch { throw new Error("Soup Wall callback returned an invalid receipt."); }
    if (receipt && typeof receipt === "object" && !Array.isArray(receipt)) {
      // Empty defer does not grant host permission or change the tool/result.
      if (Object.keys(receipt).length === 0) return;
      if (Object.keys(receipt).length === 2 && receipt.decision === "deny"
          && typeof receipt.reason === "string" && receipt.reason.length <= 9000)
        throw new Error(receipt.reason);
    }
    throw new Error("Soup Wall callback returned an unsupported receipt.");
  };
  return {
    "tool.execute.before": async (input, output) => decide("before", input, output),
    "tool.execute.after": async (input, output) => decide("after", input, output),
  };
};
