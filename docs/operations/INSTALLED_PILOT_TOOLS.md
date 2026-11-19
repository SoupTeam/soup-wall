# Installed pilot demo and support report

The selected pilot component includes the demo driver, report engine, reviewed
ROADMAP index and static report assets. Run these commands from a private working
directory after installing the component.

## Synthetic demo

```sh
agentfw pilot demo
agentfw pilot demo --help
agentfw pilot demo --run --selection "$selection" --expected-commit "$commit" \
  --strace /usr/bin/strace --output "$new_private_output"
```

The first command prints an inert plan. Running the demo requires the explicit
generated demo selection and its full source commit. The driver uses owned
fixtures and a scripted loopback provider. Its report records protected useful
work, denied effects, Ask controls and cleanup. It does not measure live-model
effectiveness. Keep failed reports when retrying and choose a new output path.

## Offline support report

```sh
agentfw pilot roadmap-support --source "$commit" \
  --evidence-dir "$private_evidence" --output "$new_private_output"
```

The component supplies the reviewed index and ROADMAP by default. Explicit
`--index`, `--roadmap` and `--decisions` retain the source tool's validation.
The output directory must be new. Open its `index.html` locally or inspect
`report.json`. Missing, historical, invalid and incomplete evidence remain
distinct from human acceptance decisions.

Use the full commit that produced the selected evidence. Keep private evidence
and generated reports in a private local directory.
