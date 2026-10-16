# SOU-63 Windows fixture correction

The first integrated Windows run exposed an Administrators-owned temporary profile in the CLI leading-hyphen regression test. The fixture now uses the same real installer bootstrap as existing MCP process fixtures before creating the native token. The token mint assertion remains unchanged, and production ownership/DACL checks remain enforced.

Local checks: all 71 MCP admission tests passed; clippy with `-D warnings` and formatting passed in the isolated source export. Windows confirmation is delegated to the native Windows CI job. [results.json](results.json) retains the failed job link, exact error, log digest and changed test source digest.

The concurrent SAML PostgreSQL browser login timed out after earlier lifecycle assertions passed. Its original failure link and log digest are retained; the job was rerun without weakening assertions. This report does not label that run successful before completion.
