#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real Linux daemon/collector proof in an explicitly disposable owned home.
Scripted stdio client: no claim of an installed Claude UI or provider execution.
No credentials, raw grants, tainted text or argument bodies enter retained evidence.
"""
import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request

sys.dont_write_bytecode = True
ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('sou78_helpers', ROOT/'scripts/mcp-profile-authoring-demo.py')
helpers = importlib.util.module_from_spec(spec)
spec.loader.exec_module(helpers)

def digest(value):
    return hashlib.sha256(json.dumps(value,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--agentfw',type=Path,required=True)
    parser.add_argument('--out',type=Path,required=True)
    args=parser.parse_args()
    checks=[]
    def check(name,passed):
        checks.append({'check':name,'passed':bool(passed)})
        if not passed: raise AssertionError(name)
    report={'format':'sou78-owned-process-proof/1','platform':sys.platform,
            'scope':'one disposable owned Claude stdio connection; scripted client; no model/UI claim','checks':checks}
    args.out.parent.mkdir(parents=True,exist_ok=True)
    try:
      if sys.platform!='linux': raise RuntimeError('Linux required')
      with tempfile.TemporaryDirectory(prefix='sou78-owned-') as tmp:
        root=Path(tmp).resolve()
        binary=root/'agentfw';shutil.copyfile(args.agentfw,binary);binary.chmod(0o755)
        env={k:v for k,v in os.environ.items() if not k.startswith('AGENTFW_')}
        env.update(HOME=str(root),USERPROFILE=str(root))
        clients=[]
        log=(root/'collector.log').open('wb')
        def run(parts,ok=True,extra=None):
            result=subprocess.run([str(binary),*map(str,parts)],env=dict(env,**(extra or {})),
                capture_output=True,text=True,timeout=90)
            if ok and result.returncode:
                # Diagnostics remain bounded and contain no mint output.
                raise RuntimeError('command failed: '+str(parts[:3])+' '+result.stderr[-2000:])
            if not ok: check('expected-refusal-'+str(len(checks)),result.returncode!=0)
            return result
        try:
            run(['install'])
            home=root/'.agentfw'
            home.chmod(0o700)
            workspace=root/'workspace';workspace.mkdir(mode=0o700)
            host=root/'claude-mcp.json'
            profile_server='claude-'+hashlib.sha256((str(host)+'\0owned').encode()).hexdigest()[:24]
            old_path=workspace/'old-output.txt';new_path=workspace/'new-output.txt'
            classifier=ROOT/'rule_baseline/rule_baseline.py'
            read_schema={'type':'object','properties':{'name':{'type':'string','minLength':1}},
                         'required':['name'],'additionalProperties':False}
            create_schema={'type':'object','properties':{'path':{'type':'string','minLength':1,'maxLength':4096},
                'content':{'type':'string','maxLength':4096}},'required':['path','content'],'additionalProperties':False}
            read={'name':'read_document','description':'Read the local inventory.', 'inputSchema':read_schema}
            obsolete={'name':'read_obsolete','description':'Read the retired local inventory.', 'inputSchema':read_schema}
            create={'name':'create_file','description':'Create one bounded local note.', 'inputSchema':create_schema}
            def compile_profile(label,tools,path):
                snapshot={'format':'sw-mcp/operator-discovery/1','server_id':profile_server,
                          'server_version':'1','tools':tools}
                declarations={'format':'sw-mcp/operator-declaration/1','server_id':profile_server,
                    'server_version':'1','snapshot_sha256':digest(snapshot),'registry_id':'sou78-'+label,'tools':[]}
                for tool in tools:
                    declarations['tools'].append({'name':tool['name'],'schema_sha256':digest(tool['inputSchema']),
                        'reviewed':True,'operator_review':'Owned fixture source inspected; create-file is native broker only.',
                        'authority':{'kind':'create_file','workspace':str(workspace),'path':str(path),
                            'classifier_sha256':helpers.digest(classifier)} if tool['name']=='create_file' else {'kind':'read_only'}})
                snap=root/(label+'-snapshot.json');decl=root/(label+'-review.json');out=root/label
                helpers.dump(snap,snapshot);helpers.dump(decl,declarations)
                run(['mcp-profile','compile','--snapshot',snap,'--declarations',decl,'--out',out])
                return out
            source_tools=[read,obsolete,create];target_tools=[read,create]
            source=compile_profile('source',source_tools,old_path)
            target=compile_profile('target',target_tools,new_path)
            manifest=root/'original-manifest.json';helpers.dump(manifest,source_tools)
            ledger=root/'child-executions.jsonl';ledger.touch()
            environment=root/'child-environment.jsonl'
            original={'command':str(Path(sys.executable).resolve()),'args':['-I','-u',
                str(ROOT/'scripts/fixtures/sou78_profile_server.py'),str(manifest),str(ledger),str(environment)]}
            host=root/'claude-mcp.json'
            initial={'mcpServers':{'owned':original,'unrelated':{'command':'untouched','env':{'KEY':'unrelated-secret'}}},
                     'settings':{'theme':'light'}}
            helpers.dump(host,initial)
            policy=root/'policy.yaml';policy.write_text('agent_policies:\n  - name: reject-unreviewed-drift\n    when: {mcp_manifest_changed: true}\n    action: deny\ndefault: allow\n')
            port=helpers.available_port()
            native=json.loads((source/'native-config.json').read_text())['native']
            native['approval']={'ttl_seconds':300}
            helpers.dump(home/'config.yaml',{'port':port,'bind':'127.0.0.1','enforce':True,'policy':str(policy),'native':native})
            run(['lifecycle','install','sou78-proof',binary,'--sha256',helpers.digest(binary)])
            run(['lifecycle','start'])
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            def api(route,body=None,native=True,proof=None,host_session=None):
                token=(home/('native-token' if native else 'token')).read_text().strip()
                headers={'authorization':'Bearer '+token,'content-type':'application/json'}
                if proof is not None:headers['x-agentfw-child-authority']=proof
                if host_session is not None:headers['x-agentfw-host-session']=host_session
                request=urllib.request.Request(f'http://127.0.0.1:{port}'+route,
                    data=None if body is None else json.dumps(body).encode(),
                    headers=headers)
                try: response=opener.open(request,timeout=5)
                except urllib.error.HTTPError as error:response=error
                with response:return response.status,json.load(response)
            def connection(operation):
                return ['mcp-connection',operation,'--path',host,'--server','owned','--home',home,'--agent',binary]
            def transition(operation,src=None,dst=None,rollback=False,approval=None,extra=None,ok=True):
                parts=['mcp-connection','profile',operation,'--path',host,'--server','owned','--home',home,'--agent',binary]
                if src is not None:
                    parts+=['--source-profile',src,'--profile',dst,'--host-session','sou78-host','--classifier-script',classifier]
                if rollback:parts+=['--rollback']
                if approval is not None:parts+=['--approval',approval]
                return run(parts,ok,extra)
            def entry():return json.loads(host.read_text())['mcpServers']['owned']
            def launch(selected=None,launch_env=None):
                selected=selected or entry()
                c=helpers.MCPClient([selected['command'],*selected['args']],launch_env or env,log,cwd=workspace);clients.append(c)
                hello=c.send({'jsonrpc':'2.0','id':1,'method':'initialize','params':{
                    'protocolVersion':'2024-11-05','capabilities':{},'clientInfo':{'name':'claude-code-scripted','version':'sou78'}}})
                check('real-collector-initialize-'+str(len(checks)),hello is not None and 'result' in json.loads(hello))
                c.send({'jsonrpc':'2.0','method':'notifications/initialized'},reply=False)
                listing=c.send({'jsonrpc':'2.0','id':2,'method':'tools/list'})
                check('real-collector-tools-list-'+str(len(checks)),listing is not None and 'result' in json.loads(listing))
                return c
            call_id=10
            def call(c,tool,arguments):
                nonlocal call_id
                call_id+=1
                return c.send({'jsonrpc':'2.0','id':call_id,'method':'tools/call','params':{
                    'name':tool,'arguments':arguments,'_meta':{'claudecode/toolUseId':f'toolu_sou78_{call_id}','progressToken':call_id}}})
            def useful(c,label):
                before=len(ledger.read_text().splitlines())
                reply=call(c,'read_document',{'name':'inventory'})
                check(label,reply is not None and b'Inventory: 7 red widgets.' in reply
                      and len(ledger.read_text().splitlines())==before+1)
            def unchanged_unrelated():
                current=json.loads(host.read_text())
                check('unrelated-settings-preserved-'+str(len(checks)),current['settings']==initial['settings']
                    and current['mcpServers']['unrelated']==initial['mcpServers']['unrelated'])
            run(connection('connect'));unchanged_unrelated()
            legacy_launcher=entry()
            baseline=launch();useful(baseline,'baseline-useful-read')
            old_registry=native['registry_sha256']
            before_instance=api('/native/v1/instance')[1]['instance_id']
            old_token=run(['child-authority','mint','--session','sou78-host','--server',profile_server,
                '--agent-id','previous-agent','--tools','read_document','--instance-id',before_instance,'--ttl-seconds','3600']).stdout.strip()
            legacy_token=run(['child-authority','mint','--session','sou78-host','--server',profile_server,
                '--tools','read_document','--ttl-seconds','3600']).stdout.strip()
            resource_token=run(['child-authority','mint','--session','sou78-host','--server',profile_server,
                '--agent-id','previous-resource-agent','--tools','read_document,create_file',
                '--resources',old_path,'--instance-id',before_instance,'--ttl-seconds','3600']).stdout.strip()
            # Supported native session/call/Ask APIs create real outstanding authority.
            native_session='retained-request'
            event={'contract_version':'sw-native/1','registry_sha256':old_registry,'session_id':native_session}
            status,reply=api('/native/v1',dict(event,event='session_start',host_session='sou78-host',
                server_id=profile_server,child_authority=old_token))
            check('old-authenticated-native-session',status==200 and reply.get('release') is True)
            status,receipt=api('/native/v1',dict(event,event='call',tool='read_document',
                args={'name':'inventory'},schema_sha256=digest(read_schema)))
            check('outstanding-old-receipt-created',status==200 and receipt.get('call_id') is not None)
            ask={'contract_version':'sw-native/1','registry_sha256':old_registry,'session_id':native_session,
                 'action':'request','source':'classifier','tool':'read_document',
                 'args':{'name':'approved-on-old-profile'},'schema_sha256':digest(read_schema)}
            status,pending=api('/native/approval/v1',ask)
            check('outstanding-ask-created',status==200 and pending.get('state')=='pending')
            run(['native-approval','approve',pending['pending_id'],'--binding',pending['binding_sha256']])
            status,approved=api('/native/approval/v1',dict(ask,action='status',pending_id=pending['pending_id']))
            check('old-ask-explicitly-approved',status==200 and approved.get('state')=='approved')
            epoch_before=int((home/'approval-policy-epoch').read_text()) if (home/'approval-policy-epoch').exists() else 0
            hook={'hook_event_name':'PostToolUse','session_id':'sou78-host','tool_name':'WebFetch',
                  'tool_input':{'url':'https://untrusted.example.test/inventory'},'tool_response':
                  'Quarterly inventory and pending retention schedule for archived records in the warehouse.'}
            check('hook-history-observed',api('/hook',hook,native=False,proof=old_token)[0]==200)
            status,_=api('/native/v1/profile-barrier',{},host_session='sou78-host')
            check('source-risk-checkpoint-before-transition',status==200)
            prior_checkpoint=json.loads((home/'mcp-profiles/risk-checkpoint.json').read_text())
            prior_host=next(s for s in prior_checkpoint['provenance']['sessions'] if s['session']=='sou78-host')
            prior_fingerprints={f[0] for f in prior_host['fingerprints']}
            check('authenticated-hook-has-real-retained-taint-before-upgrade',bool(prior_fingerprints))

            malformed=root/'malformed';shutil.copytree(target,malformed)
            (malformed/'profile.json').write_text('{}')
            config_before=(home/'config.yaml').read_bytes();host_before=host.read_bytes()
            transition('preview',source,malformed,ok=False)
            check('malformed-target-no-mutation',(home/'config.yaml').read_bytes()==config_before and host.read_bytes()==host_before)
            useful(baseline,'malformed-target-preserves-live-baseline')
            preview=json.loads(transition('preview',source,target).stdout)
            report['profiles']={'source_bundle_sha256':preview['identities']['source'],
                'target_bundle_sha256':preview['identities']['target'],'source_registry_sha256':old_registry,
                'target_registry_sha256':helpers.digest(target/'registry.json'),
                'original_server_sha256':digest(original),'policy_sha256':helpers.digest(policy)}
            external=json.loads(host.read_text());external['settings']['theme']='external'
            helpers.dump(host,external)
            transition('apply',source,target,approval=preview['approval'],ok=False)
            check('stale-preview-preserves-external-edit',json.loads(host.read_text())==external)
            host.write_bytes(host_before);host.chmod(0o600)
            library=root/'publication.so'
            subprocess.run(['cc','-shared','-fPIC','-Wall','-Wextra','-Werror',
                str(ROOT/'scripts/fixtures/connection_publication.c'),'-ldl','-o',str(library)],check=True,capture_output=True)
            def activate(src,dst,tools,rollback=False,crash=None):
                p=json.loads(transition('preview',src,dst,rollback).stdout)
                extra={'LD_PRELOAD':str(library),'SW_PUBLICATION_MODE':crash} if crash else None
                result=transition('apply',src,dst,rollback,p['approval'],extra,ok=not crash)
                if crash:
                    if result.returncode != (86 if crash=='crash-before' else 87):
                        raise RuntimeError('unexpected crash witness exit '+str(result.returncode)+': '+result.stderr[-2500:])
                    check('exact-real-process-'+crash,True)
                    before_children=len(environment.read_text().splitlines())
                    blocked=subprocess.run([legacy_launcher['command'],*legacy_launcher['args']],env=env,
                        input=b'',capture_output=True,timeout=10)
                    check('pending-transition-refuses-legacy-start-'+crash,blocked.returncode!=0
                        and len(environment.read_text().splitlines())==before_children)
                    status=json.loads(transition('status').stdout)
                    check('crash-honestly-incomplete-'+crash,status['status']=='incomplete')
                    recovered=json.loads(transition('recover').stdout)
                    check('journal-recovery-'+crash,recovered['status']=='configured')
                else:check('activation-configured-'+str(len(checks)),json.loads(result.stdout)['status']=='configured')
                helpers.dump(manifest,tools)
                unchanged_unrelated()
                status=json.loads(transition('status').stdout)
                check('configured-runtime-not-overclaimed-'+str(len(checks)),status['status']=='configured'
                    and status['daemon']=='configuration_verified' and status['host_reload']=='pending'
                    and status['runtime_execution']=='not_probed')
                return entry()
            target_launcher=activate(source,target,target_tools,crash='crash-before')
            before=len(ledger.read_text().splitlines())
            call(baseline,'read_document',{'name':'inventory'})
            check('old-live-collector-zero-execution',len(ledger.read_text().splitlines())==before)
            unbound=subprocess.run([legacy_launcher['command'],*legacy_launcher['args']],env=env,
                input=b'',capture_output=True,timeout=10)
            check('old-unversioned-launcher-refused-before-child-start',unbound.returncode!=0
                and len(ledger.read_text().splitlines())==before)
            active=launch();useful(active,'upgraded-useful-read')
            before=len(ledger.read_text().splitlines())
            call(active,'read_obsolete',{'name':'inventory'})
            call(active,'create_file',{'path':'old-output.txt','content':'must not exist'})
            check('removed-tool-and-resource-zero-effects',len(ledger.read_text().splitlines())==before and not old_path.exists())
            checkpoint=json.loads((home/'mcp-profiles/risk-checkpoint.json').read_text())
            check('authenticated-host-taint-survives-real-daemon-restart',any(s['session']=='sou78-host'
                and (s['fingerprints'] or s['literals']) for s in checkpoint['provenance']['sessions']))
            check('sticky-incomplete-floor-survives',next(s for s in checkpoint['provenance']['sessions'] if s['session']=='sou78-host')['incomplete'])
            current_host=next(s for s in checkpoint['provenance']['sessions'] if s['session']=='sou78-host')
            check('pre-transition-taint-fingerprints-retained',prior_fingerprints.issubset({f[0] for f in current_host['fingerprints']}))

            current_registry=json.loads((home/'mcp-profiles/profile-state.json').read_text())['active_bundle_sha256']
            registry=json.loads((home/'mcp-profiles/revisions'/current_registry/'native-config.json').read_text())['native']['registry_sha256']
            for name,token in [('scoped',old_token),('legacy',legacy_token),('resource',resource_token)]:
                status,reply=api('/native/v1',{'contract_version':'sw-native/1','registry_sha256':registry,
                    'session_id':'stale-'+name,'event':'session_start','host_session':'sou78-host',
                    'server_id':profile_server,'child_authority':token})
                check('previous-'+name+'-grant-refused',status!=200 and reply.get('release') is False)
                check('previous-'+name+'-rejected-for-current-authority',reply.get('error_code')==(
                    'native_child_authority_identity_required' if name=='legacy' else 'native_child_authority_instance_mismatch'))
            check('profile-switch-retires-hook-grant-epoch',int((home/'approval-policy-epoch').read_text())>epoch_before)
            status,reply=api('/native/v1',dict(event,registry_sha256=registry,event='result',tool='read_document',
                args={'name':'inventory'},call_id=receipt['call_id'],result_kind='value',delivery='model',content='late result'))
            check('old-result-receipt-refused-before-release',status!=200 and reply.get('release') is False)
            status,reply=api('/native/approval/v1',dict(ask,registry_sha256=registry,action='status',pending_id=pending['pending_id']))
            check('old-approved-ask-cannot-revive',status!=200 and reply.get('state')!='approved')
            check('old-ask-grant-files-retired',not list((home/'native-grants').glob('*.json')))
            # A retained host floor must not erase authority or taint in a fresh,
            # independent authenticated context. This is a real native broker write,
            # never a child implementation or a classifier double.
            independent='sou78-independent-context'
            instance=api('/native/v1/instance')[1]['instance_id']
            proof=run(['child-authority','mint','--session',independent,'--server',profile_server,
                '--agent-id','independent-root','--tools','read_document,create_file','--resources',new_path,
                '--instance-id',instance,'--ttl-seconds','3600']).stdout.strip()
            control_env=dict(env,AGENTFW_HOST_SESSION=independent,AGENTFW_CHILD_AUTHORITY=proof,
                AGENTFW_CLASSIFIER='rule-baseline',AGENTFW_RULE_BASELINE=str(classifier),
                AGENTFW_CLASSIFIER_PYTHON=str(Path(sys.executable).resolve()),AGENTFW_WORKSPACE=str(workspace))
            control=launch({'command':str(binary),'args':['mcp','--id',profile_server,'--native-admission','--',
                original['command'],*original['args']]},control_env)
            useful(control,'independent-current-authority-useful-read')
            before=len(ledger.read_text().splitlines())
            call(active,'create_file',{'path':'new-output.txt','content':'must remain gated for retained host'})
            check('retained-host-floor-still-gates-current-resource',not new_path.exists()
                and len(ledger.read_text().splitlines())==before)
            content='SOU78 independent bounded positive control'
            reply=call(control,'create_file',{'path':'new-output.txt','content':content})
            check('fresh-current-resource-authority-executes-through-native-broker',reply is not None
                and new_path.is_file() and new_path.read_text()==content
                and len(ledger.read_text().splitlines())==before)
            control.close()
            # Remove only this exact fixture-owned positive-control output so the
            # reviewed create-once destination remains eligible for later rollback.
            check('positive-control-output-owned-before-cleanup',new_path.is_file() and not new_path.is_symlink()
                and new_path.read_text()==content)
            new_path.unlink()
            source_launcher=activate(target,source,source_tools,rollback=True,crash='crash-after')
            restored=launch();useful(restored,'recovered-rollback-useful-read')
            activate(source,target,target_tools)
            activate(target,source,source_tools,rollback=True)
            stale=subprocess.run([source_launcher['command'],*source_launcher['args']],env=env,
                input=b'',capture_output=True,timeout=10)
            check('byte-identical-rollback-does-not-revive-stale-launcher',stale.returncode!=0)
            fresh=launch();useful(fresh,'final-rollback-useful-read')
            check('no-forbidden-broker-files',not old_path.exists() and not new_path.exists())
            env_rows=[json.loads(line) for line in environment.read_text().splitlines()]
            check('delegated-token-never-reaches-original-child',all('AGENTFW_CHILD_AUTHORITY' not in r['keys']
                and 'AGENTFW_HOST_SESSION' not in r['keys'] for r in env_rows))
            check('host-configuration-contains-no-token',old_token not in host.read_text() and legacy_token not in host.read_text())
            check('all-process-ledger-entries-are-useful-reads',all(json.loads(line)['params']['name']=='read_document'
                for line in ledger.read_text().splitlines()))
            final_checkpoint=json.loads((home/'mcp-profiles/risk-checkpoint.json').read_text())
            final_host=next(s for s in final_checkpoint['provenance']['sessions'] if s['session']=='sou78-host')
            check('rollback-retains-original-host-history',prior_fingerprints.issubset({f[0] for f in final_host['fingerprints']})
                and final_host['incomplete'] and final_checkpoint['require_scoped_authority'])
            status,reply=api('/native/v1',dict(event,registry_sha256=old_registry,event='session_start',
                host_session='sou78-host',server_id=profile_server,child_authority=resource_token,session_id='old-resource-after-rollback'))
            check('identical-rollback-rejects-old-resource-authority',status!=200
                and reply.get('error_code')=='native_child_authority_instance_mismatch')
            report['binary_sha256']=helpers.digest(binary)
            report['passed']=True
        finally:
            for c in clients:c.close()
            stopped=subprocess.run([str(binary),'lifecycle','stop'],env=env,capture_output=True,timeout=30)
            log.close()
            check('owned-daemon-stop-succeeded',stopped.returncode==0)
            status=subprocess.run([str(binary),'lifecycle','status'],env=env,capture_output=True,text=True,timeout=15)
            state=json.loads(status.stdout) if status.returncode==0 else {}
            check('owned-daemon-no-live-process',state.get('running') is False and state.get('process') is None)

    finally:
        report['passed']=bool(report.get('passed')) and all(c['passed'] for c in checks)
        report['counts']={'passed':sum(c['passed'] for c in checks),'failed':sum(not c['passed'] for c in checks),
                          'incomplete':0 if report.get('passed') else 1}
        helpers.dump(args.out,report)
    print(json.dumps({'passed':report.get('passed',False),'checks':len(checks),'evidence':str(args.out)}))

if __name__=='__main__':main()
