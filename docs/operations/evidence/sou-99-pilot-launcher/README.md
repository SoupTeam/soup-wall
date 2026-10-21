# SOU-99 launcher review qualification

`qualification.json` distinguishes three scopes: historical live Python-server fixtures, validation previews using stub executables (no host execution), and the actual installed-original-server full launcher result.

`installed-original-qualification.json` is the byte-identical report from CI run 39572797593, Linux job 119131523926, source commit de30646058cbfece63561b8fb67dbe183fca39e9. Both reviewed original profiles were installed using the accepted locked installers. The real selected Claude host executed five correlated proposals through `agentfw pilot-launch`: useful filesystem read, useful Git status, untrusted filesystem content, refused Git reset, useful filesystem continuation. The selected enforcing policy was verified by the production launcher.

The original read-only profile rejects Git reset before native call admission. The report accurately attributes that refusal to the profile guard; it does not claim that the daemon evaluated the mutation. The independent syscall observer calibrated both collectors' discovery and four useful original-server dispatches, with zero forbidden dispatches. Workspace bytes, staged Git index and HEAD were unchanged; private configuration was removed and all 27 observed owned descendants stopped. The owned loopback provider uses no paid API calls; synthetic cost fields in host output are not billing evidence.

`first-original-linux-attempt.json` preserves the initial failed qualification. Its owned test preparation incorrectly persisted a [user] section in Git config, which the accepted profile refuses. Preparation now supplies author identity in the command environment and keeps the existing bounded [core] contract. No production profile guard was relaxed or rewritten.

`review-local-verification.json` records separate macOS Rust/Python checks and their sandbox adjustments. Raw syscall traces and live child-authority/daemon secrets are never retained in this directory. The evidence-retention commit adds documentation only; executable qualification inputs remain those of the recorded source commit.
