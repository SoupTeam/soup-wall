# Original Git read outcomes

The SOU-177 diagnostic records distinguish the original response from the subsequent result-inspection decision. They contain correlation hashes, response hashes, protocol-error codes and Boolean observations. Original content, exception messages, arguments and credentials are not diagnostic fields.

`mcp_call_outcome` version 1 is an observation, not authority to execute or release content. A server tool error and an inspection refusal are different outcomes. A successful negative control is not useful Git work.

The existing project qualifier retains these records as `boundary_observations`. The projector accepts only the finite schema; unknown fields and arbitrary server text are discarded. Missing observations remain missing and must not be used to infer a failure boundary.

Run the targeted `mcp-real-filesystem.yml` workflow with `existing_project_only=true` to exercise the existing project lane and the unchanged docs-code, unicode-spaces and local-history inventories. Keep failed reports and exact source/input identities. No detector correction or successful utility claim is established by diagnostic instrumentation alone.
