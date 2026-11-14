# SPDX-License-Identifier: Apache-2.0
"""Owned inert archive controls, never native qualification evidence."""
import io
from pathlib import Path
import tarfile
import pilot_candidate as c

def populate(directory, commit, agent=b"inert synthetic Agent", tree="b" * 40, launcher=b"inert synthetic launcher"):
    source = {"commit":commit,"tree":tree,"dirty":False,"files_sha256":"c"*64,
              "cargo_lock_sha256":"d"*64,"rust_toolchain_sha256":"e"*64}
    manifest = c.canonical({"schema":"sw-pilot-front-door-component/1",
                            "source":{"commit":commit,"tree":tree},"files":[]})
    output = io.BytesIO()
    with tarfile.open(fileobj=output, mode="w", format=tarfile.USTAR_FORMAT) as package:
        info=tarfile.TarInfo("manifest.json"); info.size=len(manifest)
        package.addfile(info,io.BytesIO(manifest))
    for name,raw in (("agentfw",agent),(c.LAUNCHER,launcher),
                     (c.COMPONENT,output.getvalue()),(c.SOURCE,c.canonical(source))):
        (directory/name).write_bytes(raw)
        (directory/name).chmod(0o755 if name in ("agentfw",c.LAUNCHER) else 0o644)
    receipt={"format":c.FORMAT,"status":"built-not-qualified","toolchain":c.PIN,"lane":"release",
             "target":c.TARGET,"commands":[c.COMMAND],"source":source,"source_sha256":c.sha(c.canonical(source)),
             "tools":{n:{"version":n+" "+c.PIN+" (synthetic-control)","sha256":"f"*64} for n in ("rustc","cargo")},
             "binaries":{role:{"path":name,**c.file_record(directory/name)} for role,name in c.BINARY_NAMES.items()},
             "component":{"path":c.COMPONENT,**c.file_record(directory/c.COMPONENT)},
             "component_manifest_sha256":c.sha(manifest)}
    (directory/c.RECEIPT).write_bytes(c.canonical(receipt));(directory/c.RECEIPT).chmod(0o644)
    return receipt
