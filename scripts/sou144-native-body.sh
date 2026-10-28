set -euo pipefail
cd /home/runner/work/soup-wall/soup-wall
cargo fmt --all -- --check
cargo test --locked --offline -p agentfw --lib pilot_workspaces -- --nocapture 2>&1 | tee "$SOU144_SCRATCH/inspector-tests.log"
cargo test --locked --offline -p agentfw --lib mcp::server_profile::git -- --nocapture 2>&1 | tee "$SOU144_SCRATCH/production-validator-tests.log"
cargo test --locked --offline -p agentfw --lib selected_workspace_validation -- --nocapture 2>&1 | tee "$SOU144_SCRATCH/selected-validator-tests.log"
cargo clippy --locked --offline -p agentfw --all-targets -- -D warnings 2>&1 | tee "$SOU144_SCRATCH/clippy.log"
cargo build --locked --offline -p agentfw --bin agentfw 2>&1 | tee "$SOU144_SCRATCH/build.log"
python3 -B -m unittest discover -s scripts/tests -p test_pilot_workspace_witness.py -v 2>&1 | tee "$SOU144_SCRATCH/witness-controls.log"
python3 -B scripts/check_pilot_workspaces.py --agentfw "$CARGO_TARGET_DIR/debug/agentfw" --expected-commit e296ad2d5fcca35da481fb0a3d9c18c4c357f1bf --output "$SOU144_SCRATCH/witness"
