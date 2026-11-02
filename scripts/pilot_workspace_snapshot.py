# SPDX-License-Identifier: Apache-2.0
"""Private consented workspace generations, never a live-workspace claim or authority."""
from contextlib import contextmanager
import argparse
import ctypes
try:
    import fcntl
except ImportError:
    fcntl=None
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path, PurePosixPath
import shutil
import stat
import sys
import uuid

_spec=importlib.util.spec_from_file_location('workspace_snapshot_io',Path(__file__).with_name('pilot_update.py'))
IO=importlib.util.module_from_spec(_spec);_spec.loader.exec_module(IO)
FORMAT='sw-private-workspace-snapshot/1'
MAX_FILES=128
MAX_DIRECTORIES=128
MAX_ENTRIES=256
MAX_DEPTH=32
MAX_FILE=8*1024*1024
MAX_BYTES=32*1024*1024
RESERVE=16*1024*1024
# Capturing an installation/session store is never an approved workspace scope.
FORBIDDEN={'.env','.aws','.ssh','.claude','.codex','credentials.json','auth.json','sessions','grants','approvals',
           'pilot-providers','pilot-projects','pilot-maintenance','front-door.json','selection.json','hook-token',
           'native-token','settings.json','client-settings.json','provider-credentials.json'}


def require(ok, code):
    if not ok: raise ValueError('workspace_snapshot_'+code)


def encoded(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False,allow_nan=False).encode()


def digest(value): return hashlib.sha256(encoded(value)).hexdigest()


def identity(m): return dict(device=m.st_dev,inode=m.st_ino,uid=m.st_uid)


def stamp(m):
    return [m.st_dev,m.st_ino,m.st_uid,m.st_gid,m.st_mode,m.st_nlink,m.st_size,m.st_mtime_ns,m.st_ctime_ns]


def relative(value):
    require(isinstance(value,str) and value and len(value.encode())<=4096 and not any(ord(c)<32 or ord(c)==127 for c in value), 'path_invalid')
    path=PurePosixPath(value)
    require(not path.is_absolute() and str(path)==value and all(p not in ('.','..') for p in path.parts), 'path_invalid')
    return path


def root(path, *, private=False):
    require(os.name=='posix','platform_unsupported')
    path=Path(path)
    require(path.is_absolute() and path!=Path('/') and path!=Path.home().resolve() and path.resolve(strict=True)==path, 'canonical_root_required')
    fd=IO.open_directory(path)
    try:
        m=os.fstat(fd)
        require(m.st_uid==os.getuid() and not m.st_mode&0o022 and (not private or stat.S_IMODE(m.st_mode)==0o700), 'owned_root_required')
        return fd
    except BaseException:
        os.close(fd);raise


def separate(paths):
    values=[Path(p).resolve() for p in paths if p is not None]
    for i,a in enumerate(values):
        for b in values[:i]: require(not a.is_relative_to(b) and not b.is_relative_to(a),'overlapping_scope_or_state')


def mount(fd):
    if sys.platform!='linux': return None
    raw=Path('/proc/self/fdinfo/'+str(fd)).read_text()
    return next(line.split(':',1)[1].strip() for line in raw.splitlines() if line.startswith('mnt_id:'))


def local(fd):
    if sys.platform!='linux': return
    # statfs is inspected through an oversized aligned buffer, never guessed
    # structure offsets beyond its first native signed-long filesystem type.
    buf=(ctypes.c_long*64)();libc=ctypes.CDLL(None,use_errno=True)
    require(libc.fstatfs(fd,ctypes.byref(buf))==0,'mount_unavailable')
    require(buf[0]&0xffffffff in (0xef53,0x58465342,0x9123683e,0x01021994),'local_filesystem_required')


class Observer:
    def __init__(self):
        self.fd=None
        if sys.platform=='linux':
            self.libc=ctypes.CDLL(None,use_errno=True)
            fd=self.libc.inotify_init1(os.O_NONBLOCK|os.O_CLOEXEC)
            require(fd>=0,'observer_unavailable');self.fd=fd
    def watch(self,fd):
        if self.fd is not None:
            require(self.libc.inotify_add_watch(self.fd,os.fsencode('/proc/self/fd/'+str(fd)),0x01000fc6)>=0,'observer_unavailable')
    def check(self):
        if self.fd is not None:
            try: events=os.read(self.fd,65536)
            except BlockingIOError: return
            require(not events,'source_changed_during_capture')
    def close(self):
        if self.fd is not None: os.close(self.fd);self.fd=None


class Capture:
    """Retained no-follow source descriptors, including every ancestor in scope."""
    def __init__(self,source):
        self.source=Path(source);self.nodes=[];self.observer=Observer();self.root=None
        try:
            self.root=root(self.source);local(self.root)
            self.root_identity=identity(os.fstat(self.root));self.total=0
            self.walk(self.root,'',0,mount(self.root))
            self.check()
        except BaseException:
            self.close();raise
    def walk(self,fd,prefix,depth,mount_id):
        self.nodes.append(dict(path=prefix,kind='directory',fd=fd,stamp=stamp(os.fstat(fd))))
        require(depth<=MAX_DEPTH and sum(n['kind']=='directory' for n in self.nodes)<=MAX_DIRECTORIES,'tree_bound')
        self.observer.watch(fd)
        with os.scandir(fd) as entries:
            names=[]
            for entry in entries:
                require(len(names)<MAX_ENTRIES,'tree_bound');names.append(entry.name)
        for name in sorted(names):
            require(len(self.nodes)<MAX_ENTRIES and name.lower() not in FORBIDDEN and not name.lower().startswith('.env.'),'scope_or_entry_bound')
            path=(prefix+'/' if prefix else '')+name;relative(path)
            m=os.stat(name,dir_fd=fd,follow_symlinks=False)
            require(m.st_uid==os.getuid() and not m.st_mode&0o022 and (stat.S_ISDIR(m.st_mode) or stat.S_ISREG(m.st_mode) and m.st_nlink==1),'regular_owned_tree_required')
            child=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if stat.S_ISDIR(m.st_mode) else 0),dir_fd=fd)
            try:
                require(stamp(os.fstat(child))==stamp(m) and mount(child)==mount_id,'source_changed_or_nested_mount')
                if stat.S_ISDIR(m.st_mode):
                    owned_child=child;child=None
                    self.walk(owned_child,path,depth+1,mount_id)
                else:
                    require(sum(n['kind']=='file' for n in self.nodes)<MAX_FILES and m.st_size<=MAX_FILE,'file_bound')
                    self.total+=m.st_size;require(self.total<=MAX_BYTES,'byte_bound')
                    self.nodes.append(dict(path=path,kind='file',fd=child,stamp=stamp(m)));child=None
            finally:
                if child is not None: os.close(child)
    def scope(self):
        return [dict(path=n['path'],kind=n['kind'],stamp=n['stamp']) for n in self.nodes]
    def check(self):
        self.observer.check()
        fresh=root(self.source)
        try: require(identity(os.fstat(fresh))==self.root_identity,'source_root_changed')
        finally: os.close(fresh)
        parents={n['path']:n for n in self.nodes if n['kind']=='directory'}
        for n in self.nodes:
            require(stamp(os.fstat(n['fd']))==n['stamp'],'source_changed_during_capture')
            if n['path']:
                p=PurePosixPath(n['path']);parent=parents['' if str(p.parent)=='.' else str(p.parent)]
                require(stamp(os.stat(p.name,dir_fd=parent['fd'],follow_symlinks=False))==n['stamp'],'source_changed_during_capture')
        self.observer.check()
    def close(self):
        retained={n['fd'] for n in self.nodes}
        if self.root is not None and self.root not in retained: os.close(self.root)
        for fd in retained: os.close(fd)
        self.nodes=[];self.root=None;self.observer.close()
    def __enter__(self):return self
    def __exit__(self,*_):self.close()


def plan(capture,destination,protected):
    destination=Path(destination)
    require(destination.is_absolute() and destination.name not in ('.','..') and destination.resolve()==destination,'canonical_destination_required')
    require(not destination.exists() and not destination.is_symlink(),'destination_exists')
    with IO.Directory(destination.parent) as parent:
        local(parent.fd)
        separate([capture.source,destination])
        for path in protected: separate([capture.source,destination,path])
        parent.check()
        body=dict(format=FORMAT,source=str(capture.source),source_identity=capture.root_identity,
                  destination=str(destination),destination_parent=identity(os.fstat(parent.fd)),scope=capture.scope(),
                  limits=dict(files=MAX_FILES,directories=MAX_DIRECTORIES,entries=MAX_ENTRIES,depth=MAX_DEPTH,file_bytes=MAX_FILE,total_bytes=MAX_BYTES),
                  protected=[str(Path(p).resolve()) for p in protected])
    return body


def preview(source,destination,protected=()):
    with Capture(source) as capture:
        value=plan(capture,destination,protected)
        return dict(format=FORMAT,status='snapshot-plan',view='snapshot, never current live workspace',executed=False,
                    source=value['source'],destination=value['destination'],source_identity=value['source_identity'],
                    files=sum(n['kind']=='file' for n in capture.nodes),directories=sum(n['kind']=='directory' for n in capture.nodes),
                    bytes=capture.total,limits=value['limits'],confirmation=digest(value),content_copied=False)


def publish(parent,temporary,destination):
    libc=ctypes.CDLL(None,use_errno=True);rename=getattr(libc,'renameat2',None)
    require(sys.platform=='linux' and rename is not None,'exclusive_publication_unavailable')
    if rename(parent,os.fsencode(temporary),parent,os.fsencode(destination),1)!=0:
        raise OSError(ctypes.get_errno(),'exclusive snapshot publication refused')


def write_record(directory,name,value):
    raw=encoded(value);require(len(raw)<=65536,'receipt_bound')
    fd=os.open(name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=directory)
    try:
        with os.fdopen(os.dup(fd),'wb') as stream: stream.write(raw);stream.flush();os.fsync(stream.fileno())
        os.fchmod(fd,0o400);os.fsync(fd)
    finally:os.close(fd)
    return hashlib.sha256(raw).hexdigest()


def remove_tree(parent,name):
    # Descriptor-anchored removal; never chmod/traverse a pathname alias.
    count=[0]
    def clear(directory):
        os.fchmod(directory,0o700)
        with os.scandir(directory) as stream:
            names=[]
            for entry in stream:
                count[0]+=1;require(count[0]<=MAX_ENTRIES+8,'removal_bound');names.append(entry.name)
        for child in names:
            m=os.stat(child,dir_fd=directory,follow_symlinks=False)
            require(m.st_uid==os.getuid(),'removal_owner_changed')
            if stat.S_ISDIR(m.st_mode):
                fd=os.open(child,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=directory)
                try: require(identity(os.fstat(fd))==identity(m),'removal_changed');clear(fd)
                finally: os.close(fd)
                os.rmdir(child,dir_fd=directory)
            else: os.unlink(child,dir_fd=directory)
    fd=os.open(name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent)
    try:clear(fd)
    finally:os.close(fd)
    os.rmdir(name,dir_fd=parent)


def create(source,destination,confirmation,protected=()):
    require(sys.platform=='linux','capture_platform_unsupported')
    destination=Path(destination)
    with Capture(source) as capture, IO.Directory(destination.parent) as parent:
        value=plan(capture,destination,protected)
        require(confirmation==digest(value),'exact_confirmation_required')
        available=os.fstatvfs(parent.fd)
        require(available.f_bavail*available.f_frsize>=capture.total+RESERVE,'insufficient_space')
        temporary='.snapshot-'+uuid.uuid4().hex
        os.mkdir(temporary,0o700,dir_fd=parent.fd)
        stage=os.open(temporary,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=parent.fd)
        published=False
        try:
            os.mkdir('workspace',0o700,dir_fd=stage)
            workspace=os.open('workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=stage)
            outputs={'':workspace};entries=[]
            try:
                for n in capture.nodes[1:]:
                    p=PurePosixPath(n['path']);out_parent=outputs['' if str(p.parent)=='.' else str(p.parent)]
                    if n['kind']=='directory':
                        os.mkdir(p.name,0o700,dir_fd=out_parent)
                        fd=os.open(p.name,os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=out_parent)
                        outputs[n['path']]=fd
                        entries.append(dict(path=n['path'],kind='directory',size=0,sha256='',identity=identity(os.fstat(fd))))
                    else:
                        fd=os.open(p.name,os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=out_parent)
                        h=hashlib.sha256();count=0
                        try:
                            os.lseek(n['fd'],0,os.SEEK_SET)
                            credential_tail=b''
                            with os.fdopen(os.dup(fd),'wb') as stream:
                                while block:=os.read(n['fd'],65536):
                                    count+=len(block);require(count<=n['stamp'][6],'source_changed_during_capture')
                                    inspected=credential_tail+block
                                    require(not any(marker in inspected for marker in (b'sk-ant-api',b'-----BEGIN PRIVATE KEY-----',b'-----BEGIN RSA PRIVATE KEY-----')), 'credential_material_refused')
                                    require(re.search(rb"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}|(?:ANTHROPIC_API_KEY|OPENAI_API_KEY|ANTHROPIC_AUTH_TOKEN)\s*[:=]\s*['\"]?[A-Za-z0-9_-]{12,}", inspected) is None, 'credential_material_refused')
                                    credential_tail=inspected[-256:]
                                    stream.write(block);h.update(block)
                                require(count==n['stamp'][6],'source_changed_during_capture')
                                stream.flush();os.fsync(stream.fileno())
                            os.fchmod(fd,0o400);os.fsync(fd)
                            entries.append(dict(path=n['path'],kind='file',size=count,sha256=h.hexdigest(),identity=identity(os.fstat(fd))))
                        finally:os.close(fd)
                capture.check();parent.check()
                for fd in reversed(list(outputs.values())):os.fchmod(fd,0o500);os.fsync(fd)
                entries.sort(key=lambda e:e['path'])
                tree=digest([{k:v for k,v in e.items() if k!='identity'} for e in entries])
                lease=os.open('lease',os.O_CREAT|os.O_EXCL|os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC,0o600,dir_fd=stage)
                try: lease_id=identity(os.fstat(lease));os.fsync(lease)
                finally:os.close(lease)
                receipt=dict(format=FORMAT,view='snapshot',source=str(capture.source),source_identity=capture.root_identity,
                             source_scope_sha256=digest(capture.scope()),tree_sha256=tree,entries=entries,
                             generation_identity=identity(os.fstat(stage)),workspace_identity=identity(os.fstat(workspace)),lease_identity=lease_id)
                receipt_sha=write_record(stage,'receipt.json',receipt)
                write_record(stage,'complete.json',dict(format=FORMAT,receipt_sha256=receipt_sha,generation_identity=receipt['generation_identity']))
                os.fsync(stage);capture.check();parent.check()
                publish(parent.fd,temporary,destination.name);published=True;os.fsync(parent.fd);parent.check()
            finally:
                for fd in outputs.values():os.close(fd)
        finally:
            os.close(stage)
            if not published:remove_tree(parent.fd,temporary)
    return inspect(destination)


def record(fd,name):
    file=os.open(name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=fd)
    try:
        m=os.fstat(file)
        require(stat.S_ISREG(m.st_mode) and m.st_uid==os.getuid() and stat.S_IMODE(m.st_mode)==0o400 and m.st_nlink==1 and m.st_size<=65536,'private_receipt_required')
        raw=os.read(file,65537)
        require(len(raw)==m.st_size and stamp(os.fstat(file))==stamp(m)==stamp(os.stat(name,dir_fd=fd,follow_symlinks=False)),'receipt_changed')
        value=IO.decode(raw);require(encoded(value)==raw,'receipt_encoding_invalid')
        return value,hashlib.sha256(raw).hexdigest()
    finally:os.close(file)


def tree(fd,entries):
    expected={e['path']:e for e in entries};seen=set();total=0
    def walk(directory,prefix='',depth=0):
        nonlocal total
        require(depth<=MAX_DEPTH,'tree_bound')
        with os.scandir(directory) as names:
            for n in names:
                path=(prefix+'/' if prefix else '')+n.name;relative(path)
                require(path in expected and path not in seen and len(seen)<MAX_ENTRIES,'tree_changed')
                seen.add(path);e=expected[path]
                child=os.open(n.name,os.O_RDONLY|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC|(os.O_DIRECTORY if e['kind']=='directory' else 0),dir_fd=directory)
                try:
                    before=os.fstat(child)
                    require(identity(before)==e['identity'] and before.st_uid==os.getuid() and
                            stat.S_IMODE(before.st_mode)==(0o500 if e['kind']=='directory' else 0o400),'snapshot_object_changed')
                    if e['kind']=='directory':walk(child,path,depth+1)
                    else:
                        require(stat.S_ISREG(before.st_mode) and before.st_nlink==1 and before.st_size==e['size']<=MAX_FILE,'snapshot_object_changed')
                        h=hashlib.sha256();count=0
                        while block:=os.read(child,65536):
                            count+=len(block);total+=len(block);require(count<=e['size'] and total<=MAX_BYTES,'byte_bound');h.update(block)
                        require(count==e['size'] and h.hexdigest()==e['sha256'],'snapshot_content_changed')
                    require(stamp(os.fstat(child))==stamp(before)==stamp(os.stat(n.name,dir_fd=directory,follow_symlinks=False)),'snapshot_object_changed')
                finally:os.close(child)
    walk(fd);require(seen==set(expected),'incomplete_generation')


def load(destination):
    destination=Path(destination)
    with IO.Directory(destination) as generation:
        require(set(os.listdir(generation.fd))=={'workspace','receipt.json','complete.json','lease'},'incomplete_generation')
        receipt,sha=record(generation.fd,'receipt.json');complete,_=record(generation.fd,'complete.json')
        require(set(receipt)=={'format','view','source','source_identity','source_scope_sha256','tree_sha256','entries','generation_identity','workspace_identity','lease_identity'} and receipt['format']==FORMAT and receipt['view']=='snapshot','receipt_schema')
        require(complete==dict(format=FORMAT,receipt_sha256=sha,generation_identity=identity(os.fstat(generation.fd))) and
                receipt['generation_identity']==identity(os.fstat(generation.fd)),'generation_changed')
        entries=receipt['entries'];require(isinstance(entries,list) and len(entries)<=MAX_ENTRIES and
            all(isinstance(e,dict) and set(e)=={'path','kind','size','sha256','identity'} and e['kind'] in ('file','directory') for e in entries),'receipt_schema')
        require([e['path'] for e in entries]==sorted(set(e['path'] for e in entries)) and
                digest([{k:v for k,v in e.items() if k!='identity'} for e in entries])==receipt['tree_sha256'],'tree_hash_changed')
        workspace=os.open('workspace',os.O_RDONLY|os.O_DIRECTORY|os.O_NOFOLLOW|os.O_CLOEXEC,dir_fd=generation.fd)
        try:
            require(identity(os.fstat(workspace))==receipt['workspace_identity'] and stat.S_IMODE(os.fstat(workspace).st_mode)==0o500,'snapshot_root_changed')
            local(workspace);tree(workspace,entries)
        finally:os.close(workspace)
        generation.check()
        return dict(format=FORMAT,generation=str(destination),generationIdentity=receipt['generation_identity'],
                    workspaceIdentity=receipt['workspace_identity'],receiptSha256=sha,treeSha256=receipt['tree_sha256'],
                    entries=entries,leaseIdentity=receipt['lease_identity'])


def inspect(destination):
    binding=load(destination)
    with IO.Directory(destination) as generation: receipt,_=record(generation.fd,'receipt.json')
    try:
        with Capture(receipt['source']) as live:
            same_scope=digest(live.scope())==receipt['source_scope_sha256']
        current='same-recorded-metadata' if same_scope else 'changed-since-capture'
    except (OSError,ValueError):current='unavailable-or-unsupported'
    return dict(format=FORMAT,status='complete-snapshot',view='snapshot, never current live workspace',executed=False,
                workspace=str(Path(destination)/'workspace'),binding=binding,captured_source=dict(path=receipt['source'],identity=receipt['source_identity']),
                current_source=current,content_tree_sha256=binding['treeSha256'],removal_confirmation=digest(binding))


def verify(binding):
    require(isinstance(binding,dict) and binding==load(binding.get('generation','')),'binding_changed')
    return binding


@contextmanager
def hold(binding,*,exclusive=False):
    require(fcntl is not None,'platform_unsupported')
    with IO.Directory(binding['generation']) as generation:
        lease=os.open('lease',os.O_RDWR|os.O_NOFOLLOW|os.O_NONBLOCK|os.O_CLOEXEC,dir_fd=generation.fd)
        try:
            m=os.fstat(lease)
            require(identity(m)==binding['leaseIdentity'] and stat.S_ISREG(m.st_mode) and stat.S_IMODE(m.st_mode)==0o600 and m.st_nlink==1,'lease_changed')
            try:fcntl.flock(lease,(fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)|fcntl.LOCK_NB)
            except BlockingIOError:raise ValueError('workspace_snapshot_in_use') from None
            generation.check();verify(binding)
            yield
        finally:os.close(lease)


def remove(destination,confirmation):
    binding=load(destination);require(confirmation==digest(binding),'exact_removal_confirmation_required')
    with hold(binding,exclusive=True), IO.Directory(Path(destination).parent) as parent:
        verify(binding);parent.check()
        withdrawn='.snapshot-removed-'+uuid.uuid4().hex
        publish(parent.fd,Path(destination).name,withdrawn)
        os.fsync(parent.fd)
        remove_tree(parent.fd,withdrawn);os.fsync(parent.fd)
    return dict(format=FORMAT,status='snapshot-removed',executed=False,source_modified=False)


def main(argv,front=None):
    parser=argparse.ArgumentParser(description=__doc__);commands=parser.add_subparsers(dest='action',required=True)
    for action in ('preview','create'):
        p=commands.add_parser(action);p.add_argument('--source',type=Path,required=True);p.add_argument('--destination',type=Path,required=True)
        p.add_argument('--protected-root',type=Path,action='append',default=[])
        if action=='create':p.add_argument('--confirm',required=True)
    for action in ('inspect','remove'):
        p=commands.add_parser(action);p.add_argument('--snapshot',type=Path,required=True)
        if action=='remove':p.add_argument('--confirm',required=True)
    args=parser.parse_args(argv)
    try:
        if args.action in ('preview','create'):
            protected=list(args.protected_root)
            if front is not None:
                home=front.snapshot_home
                protected.extend([home,front.ROOT])
                # Existing named projects are known protected scopes, never adopted.
                profiles=front.provider_profiles();presets=front.load('snapshot_project_catalog','pilot_project_presets.py')
                if Path(home).exists():
                    with presets.Store(home,profiles) as store:
                        for row in store.read()['records'].values():
                            for r in row['binding']['workspaces'].values():
                                project=Path(r['path']);separate([args.destination,project])
                                if not args.source.is_relative_to(project):protected.append(project)
            # Protected scopes may overlap each other; require disjointness only
            # with the source/destination rather than between installation roots.
            protected=list(dict.fromkeys(protected))
            for path in protected: separate([args.source,args.destination,path])
            result=preview(args.source,args.destination,protected) if args.action=='preview' else create(args.source,args.destination,args.confirm,protected)
        else:result=inspect(args.snapshot) if args.action=='inspect' else remove(args.snapshot,args.confirm)
        print(json.dumps(result,sort_keys=True));return 0
    except (OSError,ValueError,KeyError,TypeError) as error:
        code=str(error)
        print(json.dumps(dict(format=FORMAT,status='refused',view='snapshot',executed=False,reason=code if code.startswith('workspace_snapshot_') else 'workspace_snapshot_input_or_storage_failure')))
        return 2
