set -euo pipefail
cd "$SOU145_SOURCE"
python3 - <<'PY'
import os,pathlib
assert os.geteuid()!=0 and os.statvfs(os.environ['SOU145_SOURCE']).f_flag & os.ST_RDONLY
s=pathlib.Path('/proc/self/status').read_text()
assert all(int(line.split(':')[1].strip(),16)==0 for line in s.splitlines() if line.startswith(('CapEff:','CapPrm:','CapAmb:','CapInh:')))
PY
meson setup "$SOU145_SCRATCH/bwrap-build" "$SOU145_SCRATCH/bwrap-source" -Dtests=false -Dman=disabled -Dselinux=disabled -Dbash_completion=disabled -Dzsh_completion=disabled
meson compile -C "$SOU145_SCRATCH/bwrap-build"
make -C "$SOU145_SCRATCH/git-source" -j4 NO_CURL=YesPlease NO_EXPAT=YesPlease NO_TCLTK=YesPlease NO_GETTEXT=YesPlease NO_OPENSSL=YesPlease git
cargo build --locked --offline -p agentfw --bins --message-format=json > "$SOU145_SCRATCH/build.jsonl"
cargo test --locked --offline -p agentfw --lib --no-run --message-format=json > "$SOU145_SCRATCH/test-build.jsonl"
python3 - <<'PY'
import os,json,hashlib,subprocess
from pathlib import Path
s=Path(os.environ['SOU145_SCRATCH']); source=Path(os.environ['SOU145_SOURCE'])
records=[json.loads(line) for line in (s/'test-build.jsonl').read_text().splitlines()]
paths=[r['executable'] for r in records if r.get('reason')=='compiler-artifact' and r.get('target',{}).get('name')=='agentfw' and r.get('profile',{}).get('test') and r.get('executable')]
assert len(paths)==1
(s/'library-path.txt').write_text(paths[0]+'\n')
roles={'agentfw':s/'target/debug/agentfw','git_launcher':s/'target/debug/agentfw-git-sandbox','sandbox_tests':Path(paths[0]),'git':s/'git-source/git','bwrap':s/'bwrap-build/bwrap'}
assert subprocess.check_output(['git','rev-parse','HEAD'],cwd=source,text=True).strip()=='119e6962d83fd1298f2092f6d20b2950167fe371'
record={'source':'119e6962d83fd1298f2092f6d20b2950167fe371','tree':subprocess.check_output(['git','rev-parse','HEAD^{tree}'],cwd=source,text=True).strip(),'source_read_only':True,'network':'private-loopback-only','files':{name:hashlib.sha256(path.read_bytes()).hexdigest() for name,path in roles.items()}}
(s/'build-record.json').write_text(json.dumps(record,indent=2)+'\n')
PY
