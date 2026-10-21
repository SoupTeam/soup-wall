# WSL installed-pilot prerequisites

This opt-in path targets Ubuntu 24.04 on WSL2, Linux x86-64, using the
[existing installed-pilot harness](INSTALLED_PILOT_QUALIFICATION.md).
Prerequisite success is not active protection or runtime acceptance. A real
WSL run must still complete every useful/refusal/recovery case in that harness.
Native Linux results and simulated-kernel unit tests cannot replace it.

## First diagnostic

From Windows, inspect `wsl.exe --status` and `wsl.exe --list --verbose`.
A default version of 2 with no installed distribution means the environment
is **unavailable** for this pilot. It does not establish an executable WSL2
installation. Installation and host configuration remain operator decisions.

Inside the intended Ubuntu distribution, as an ordinary user, prepare a
dedicated stage parent:

```sh
mkdir -m 700 "$HOME/wall-pilot"
python3 -B scripts/qualify-installed-pilot.py --wsl-preflight \
  --wsl-root "$HOME/wall-pilot"
```

Without the existing exact runtime selection, this reports filesystem/owner
observations but returns nonzero with `exact_runtime_selection_required`.
It installs nothing, starts no Agent and makes no provider calls.

After preparing the exact binaries and selection described by the existing
harness, include `--selection /home/USER/private/selection.json` and
`--expected-commit FULL_REVIEWED_COMMIT`. Only validated selected executables
are eligible for the bubblewrap probe. The namespace probes have a five-second
deadline each and discard child output. No sysctl, security policy, privilege
or runner setting is modified.

The result distinguishes:

- `ready`: observed prerequisite checks passed; runtime protection is unmeasured.
- `incompatible`: an existing prerequisite refused the behavioral probe, or
  the stage directory is not private and owned.
- `unavailable`: a required file, executable, observation or bounded probe
  could not be obtained.
- `unsupported`: the environment is outside this initial qualification scope.

Windows paths, DrvFS/9p, UNC/CIFS and unknown filesystems are refused. The first
scope permits ext4; stage and report roots must resolve under `/home`.
Checks use mount boundaries, including nested mounts and resolved symlinks,
rather than trusting a path prefix. Selected runtimes may reside in Linux
system directories such as `/usr`; each selected file's mount is checked.
The ordinary native Linux invocation retains its previous defaults.

## Opt-in qualification

Use a clean, reviewed checkout and freshly recorded exact selection:

```sh
python3 -B scripts/qualify-installed-pilot.py --run \
  --wsl-root "$HOME/wall-pilot" \
  --selection /home/USER/private/selection.json \
  --expected-commit FULL_REVIEWED_COMMIT \
  --output /home/USER/private/new-wsl-run
```

The private installation is staged below the explicit root. Child negative
controls inherit this WSL requirement. A failed prerequisite prevents profile
preparation and host execution, and its diagnostic stays in `report.json`.
The existing denominator, source checks, original sandbox positives, independent
refusal witnesses and owned-cleanup requirements remain in force.

Follow each failed check's `next_step`; rerun using a new output directory
after correcting the selected environment. Do not enable privileged host
settings or accept an unconstrained server to turn a failure green.
The optional `resource_budgets` observation reports the current cgroup v2
membership's CPU, memory and PID controllers and writable delegation. Missing
delegation stays `unavailable`; even available prerequisites do not establish
enforcement, and `advertised` remains false. This preflight configures no limits.
Real recovery, signal handling, foreign-process refusal and cleanup still need
the actual installed run; this increment does not certify those behaviors.

## Current evidence boundary

No WSL acceptance archive accompanies this diagnostic increment. Code-level
diagnostic controls are independent of the outstanding native run. Do not treat
the presence of this entry point as a claim that WSL runtime qualification passed.
