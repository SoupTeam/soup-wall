#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real Console + Agent, SQLite/TLS PostgreSQL and Chromium fleet walkthrough.
Synthetic isolated tenants only. Credentials/logs remain in the temporary directory.
"""
import argparse
from contextlib import ExitStack
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
import re
from pathlib import Path
import secrets
import subprocess
import tempfile
import urllib.error

ROOT=Path(__file__).resolve().parents[1]
def module(name,file):
    spec=importlib.util.spec_from_file_location(name,ROOT/'scripts'/file)
    value=importlib.util.module_from_spec(spec);spec.loader.exec_module(value);return value
D=module('fleet_managed_helpers','managed-policy-demo.py')

def main():
    parser=argparse.ArgumentParser();parser.add_argument('--backend',choices=['sqlite','postgres'],required=True);parser.add_argument('--output',type=Path,required=True);args=parser.parse_args()
    from playwright.sync_api import sync_playwright, expect
    args.output.mkdir(parents=True,exist_ok=True)
    checks={}; evidence={}
    def check(name,condition):
        checks[name]=bool(condition)
        if not condition:raise AssertionError(name)
        print('PASS:',name,flush=True)
    console_binary=ROOT/'target/debug/llm-firewall'; agent_binary=ROOT/'target/debug/agentfw'
    with tempfile.TemporaryDirectory(prefix='fleet-witness-') as folder, ExitStack() as stack:
        temp=Path(folder); cd=temp/'console';cd.mkdir();home=temp/'home';(home/'.agentfw').mkdir(parents=True)
        cp,ap=D.port(),D.port();console=f'http://127.0.0.1:{cp}';agent=f'http://127.0.0.1:{ap}'
        owner=secrets.token_urlsafe(32)
        env={k:v for k,v in os.environ.items() if not k.startswith(('SOUP_MANAGED_AGENT_','SOUP_AGENT_POLICY_','LLM_FW_','OPENAI_'))}
        env.update(LLM_FW_ADMIN_TOKEN=owner,SOUP_AGENT_POLICY_KEY_ID='fleet-issuer',SOUP_AGENT_POLICY_SEED_HEX=secrets.token_hex(32),SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED=secrets.token_hex(32))
        if args.backend=='postgres':
            helpers=module('fleet_postgres_helpers','keycloak-oidc-acceptance.py')
            ca,(cert,key),_=helpers.vendor.certificate_files(temp)
            env['LLM_FW_POSTGRES_CA_CERT_FILE']=str(ca)
            database=helpers.FixtureDatabase(temp,env,stack,postgres=True,cert=cert,key=key)
            config=database.configuration()
        else:config='  backend: sqlite\n  database_path: "fleet.sqlite"\n'
        (cd/'firewall.yaml').write_text(f'bind: "127.0.0.1:{cp}"\ntenant_store:\n  enabled: true\n'+config,encoding='utf-8')
        if args.backend=='postgres':
            migrate=subprocess.run([str(console_binary),'migrate'],cwd=cd,env=env,capture_output=True,timeout=90)
            check('explicit-postgres-migration',migrate.returncode==0)
        D.proc(stack,[str(console_binary)],cd,env,temp/'console.log')
        D.wait_for('Console',lambda: D.request('GET',console+'/healthz')[0]==200)
        headers={'x-llm-firewall-admin-token':'Bearer '+owner}
        def req(method,path,payload=None,auth=headers):return D.request(method,console+path,payload,auth)[1]
        def code(method,path,auth=None,payload=None):
            try:return D.request(method,console+path,payload,auth)[0]
            except urllib.error.HTTPError as error:return error.code
        ta=req('POST','/admin/v1/tenants',{'name':'Fleet Alpha'})['id'];tb=req('POST','/admin/v1/tenants',{'name':'Fleet Beta'})['id']
        base=f'/admin/v1/tenants/{ta}'; fleet=base+'/agent-fleet'; ab=base+'/agents/agent-demo'
        viewer=req('POST','/admin/v1/admins',{'name':'Fleet viewer','role':'viewer'})['token'];view={'x-llm-firewall-admin-token':'Bearer '+viewer}
        credentials={}
        for name in ['agent-demo','no-history','revoked','awaiting-ack']:
            credentials[name]=req('POST',base+'/agents',{'agent_id':name})['token']
        req('POST',base+'/agents/revoked/revoke',{})
        req('POST',f'/admin/v1/tenants/{tb}/agents',{'agent_id':'agent-demo'})
        issuer=req('GET','/admin/v1/managed-issuer')
        def revision(path,name):
            req('POST',path+'/revisions',{'revision':name,'policy_yaml':'default: deny\n'})
            req('POST',path+'/revisions/'+name+'/approve',{})
        revision(ab,'stable');req('POST',ab+'/revisions/stable/deploy',{})
        otherbase=base+'/agents/awaiting-ack';revision(otherbase,'delivery');req('POST',otherbase+'/revisions/delivery/deploy',{})
        req('GET','/agent/v1/policy',auth={'Authorization':'Bearer '+credentials['awaiting-ack']})
        (home/'.agentfw/config.yaml').write_text(f'port: {ap}\nenforce: true\n',encoding='utf-8')
        agentenv={k:v for k,v in env.items() if not k.startswith(('SOUP_','LLM_FW_'))}
        agentenv.update(HOME=str(home),USERPROFILE=str(home),SOUP_MANAGED_AGENT_CONSOLE=console+'/',SOUP_MANAGED_AGENT_TOKEN=credentials['agent-demo'],SOUP_MANAGED_AGENT_TENANT=ta,SOUP_MANAGED_AGENT_ID='agent-demo',SOUP_MANAGED_AGENT_KEY_ID='fleet-issuer',SOUP_MANAGED_AGENT_PUBLIC_KEY_HEX=issuer['public_key_hex'])
        process=D.proc(stack,[str(agent_binary),'serve'],temp,agentenv,temp/'agent-first.log')
        def detail():return req('GET',fleet+'/agent-demo',auth=view)
        applied=D.wait_for('real Agent acknowledgement',lambda:(lambda d:d if d['agent']['latest_issued']['recorded_state']=='applied' else None)(detail()),timeout=90)
        live=D.wait_for('Agent health listener',lambda: D.request('GET',agent+'/health')[1].get('managed_policy'),timeout=90)
        check('real-Agent-applied-exact-issued-identity',live['policy_sha256']==applied['agent']['last_reported_applied']['policy_sha256'] and live['deployment_sequence']==1)
        evidence['applied']=applied
        process.terminate();process.wait(timeout=10)
        req('POST',ab+'/revisions/stable/deploy',{'issuer_key_id':'untrusted'})
        pending=detail();check('new-pending-keeps-historical-applied',pending['agent']['latest_issued']['recorded_state']=='issued' and pending['agent']['last_reported_applied']['sequence']=='1');evidence['pending']=pending
        hp=req('GET',fleet+'/agent-demo?limit=1',auth=view);older=req('GET',fleet+'/agent-demo?limit=1&before_sequence='+str(hp['next_before_sequence']),auth=view)
        check('history-keyset-preserves-separate-last-applied',hp['deployments'][0]['sequence']=='2' and older['deployments'][0]['sequence']=='1' and hp['agent']['last_reported_applied']['sequence']=='1')
        check('missing-auth-refused',code('GET',fleet)==401)
        check('agent-credential-not-viewer',code('GET',fleet,{'x-llm-firewall-admin-token':'Bearer '+credentials['agent-demo']})==401)
        check('viewer-cannot-enroll',code('POST',base+'/agents',view,{'agent_id':'forbidden'})==403)
        check('unknown-tenant-404',code('GET','/admin/v1/tenants/unknown/agent-fleet',view)==404)
        check('cross-tenant-agent-404',code('GET',f'/admin/v1/tenants/{tb}/agent-fleet/awaiting-ack',view)==404)
        beta=req('GET',f'/admin/v1/tenants/{tb}/agent-fleet/agent-demo',auth=view)
        check('same-Agent-ID-is-tenant-bound',beta['agent']['tenant_id']==tb and beta['agent']['latest_issued'] is None)
        for q in ['limit=0','limit=101','after=..%2Fx','enrollment=bogus','delivery=bogus','extra=x']:
            check('invalid-query-'+q.split('=')[0]+'-'+q.split('=')[1],code('GET',fleet+'?'+q,view)==400)
        first=req('GET',fleet+'?limit=2',auth=view);second=req('GET',fleet+'?limit=2&after='+first['next_after'],auth=view)
        check('keyset-pages-no-loss-or-duplicates',len({a['agent_id'] for a in first['agents']+second['agents']})==4 and second['next_after'] is None)
        revoked=req('GET',fleet+'?enrollment=revoked&delivery=no_history',auth=view)
        check('revoked-no-history-filter',len(revoked['agents'])==1 and revoked['agents'][0]['agent_id']=='revoked')
        delivered=req('GET',fleet+'?delivery=delivered',auth=view)
        check('recorded-delivered-without-applied',len(delivered['agents'])==1 and delivered['agents'][0]['last_reported_applied'] is None)
        with sync_playwright() as playwright, ExitStack() as browser_stack:
            browser=playwright.chromium.launch(headless=True);browser_stack.callback(browser.close)
            context=browser.new_context(viewport={'width':1440,'height':1000});page=context.new_page()
            page.goto(console+'/admin');page.locator('#admin-token').fill(viewer);page.locator('#unlock-form button').click();expect(page.locator('#console')).to_be_visible()
            page.locator('#tenant-list button').filter(has_text='Fleet Alpha').click()
            expect(page.locator('#fleet-list')).to_contain_text('agent-demo');page.get_by_role('button',name='agent-demo',exact=True).click()
            expect(page.locator('#fleet-agent-detail')).to_contain_text('Latest deployment is pending')
            page.locator('#fleet-panel').screenshot(path=str(args.output/'pending.png'))
            # Exercise the production history cursor with a smaller server page.
            def small_history(route):
                response=route.fetch(url=route.request.url.replace('limit=25','limit=1'))
                route.fulfill(response=response)
            page.route('**'+fleet+'/agent-demo?*',small_history)
            page.get_by_role('button',name='agent-demo',exact=True).click()
            expect(page.locator('#fleet-history-next')).to_be_enabled()
            page.locator('#fleet-history-next').click()
            expect(page.locator('#fleet-agent-detail')).to_contain_text('#2')
            expect(page.locator('#fleet-agent-detail')).to_contain_text('#1')
            expect(page.locator('#fleet-history-next')).to_be_disabled()
            check('browser-older-history-retains-latest-and-last-applied',True)
            page.unroute('**'+fleet+'/agent-demo?*',small_history)
            check('browser-viewer-read-only',page.locator('#fleet-panel').get_by_role('button',name=re.compile(r'^(Enroll|Revoke|Deploy|Rollback)(?:$|\s)',re.I)).count()==0 and page.locator('#admin-token').input_value()=='')
            check('browser-no-token-storage',page.evaluate('localStorage.length === 0 && sessionStorage.length === 0'))
            # Force a late success even after AbortController cancellation to prove epoch guards.
            page.evaluate('''() => { const real=window.fetch; window.fetch=(url,options={})=>{const {signal,...rest}=options;return real(url,rest)}; }''')
            held=[]
            def hold(route):held.append(route)
            page.route('**'+fleet+'?*',hold)
            page.locator('#fleet-refresh').click();page.wait_for_timeout(100)
            check('browser-pending-request-held',len(held)==1 and 'Loading' in page.locator('#fleet-status').inner_text())
            page.locator('#tenant-list button').filter(has_text='Fleet Beta').click();expect(page.locator('#fleet-list')).to_contain_text('agent-demo')
            response=held[0].fetch();held[0].fulfill(response=response);page.unroute('**'+fleet+'?*',hold)
            page.wait_for_timeout(100)
            check('browser-stale-tenant-response-discarded','awaiting-ack' not in page.locator('#fleet-list').inner_text())
            page.get_by_role('button',name='agent-demo',exact=True).click();expect(page.locator('#fleet-agent-detail')).to_contain_text('No deployment history')
            page.screenshot(path=str(args.output/'tenant-beta.png'),full_page=True)
            page.locator('#tenant-list button').filter(has_text='Fleet Alpha').click();expect(page.locator('#fleet-list')).to_contain_text('revoked')
            page.locator('#fleet-prefix').fill('not-found');page.locator('#fleet-filter button').click();expect(page.locator('#fleet-list')).to_contain_text('No Agents match')
            page.locator('#fleet-prefix').fill('');page.locator('#fleet-filter button').click();expect(page.locator('#fleet-list')).to_contain_text('revoked')
            def fail(route):route.fulfill(status=503,content_type='application/json',body='{}')
            page.route('**'+fleet+'?*',fail);page.locator('#fleet-refresh').click();expect(page.locator('#fleet-status')).to_contain_text('Unable to load');check('browser-error-clears-old-list',page.locator('#fleet-list').inner_text()=='');page.unroute('**'+fleet+'?*',fail)
            process=D.proc(stack,[str(agent_binary),'serve'],temp,agentenv,temp/'agent-rejected.log')
            rejected=D.wait_for('real Agent rejection',lambda:(lambda d:d if d['agent']['latest_issued']['recorded_state']=='rejected' else None)(detail()),timeout=90)
            check('rejected-keeps-historical-applied',rejected['agent']['last_reported_applied']['sequence']=='1' and rejected['agent']['latest_issued']['sequence']=='2');evidence['rejected']=rejected
            check('real-Agent-keeps-previous-active-policy',D.wait_for('restarted Agent health listener',lambda: D.request('GET',agent+'/health')[1].get('managed_policy'),timeout=90)['deployment_sequence']==1)
            page.locator('#fleet-refresh').click();expect(page.locator('#fleet-list')).to_contain_text('rejected');page.get_by_role('button',name='agent-demo',exact=True).click();expect(page.locator('#fleet-agent-detail')).to_contain_text('Latest deployment was rejected')
            page.clock.set_fixed_time(datetime.fromtimestamp(rejected['agent']['last_reported_applied']['reported_applied_at_unix']+600, tz=timezone.utc))
            page.get_by_role('button',name='agent-demo',exact=True).click();expect(page.locator('#fleet-agent-detail')).to_contain_text('10 min old — historical evidence (5+ min)')
            page.locator('#fleet-panel').screenshot(path=str(args.output/'rejected-historical.png'))
            check('browser-loading-empty-error-pending-rejected-and-stale-walkthrough',True)
        for item in evidence.values():
            raw=json.dumps(item);check('sanitized-'+item['agent']['latest_issued']['recorded_state'],all(s not in raw for s in [owner,viewer,*credentials.values(),env['SOUP_AGENT_POLICY_SEED_HEX'],env['SOUP_AGENT_POLICY_SEED_HEX_UNTRUSTED'],'token_hash','policy_yaml','bundle_json','signature_hex','default: deny',str(temp)]))
            check('unknown-runtime-'+item['agent']['latest_issued']['recorded_state'],item['agent']['current_liveness']=='unknown' and item['agent']['runtime_coverage']=='unknown' and item['agent']['registry_identity'] is None)
        report={'scope':'synthetic real Console/Agent and Chromium; not live fleet coverage','backend':args.backend,'source':subprocess.check_output(['git','rev-parse','HEAD'],cwd=ROOT,text=True).strip(),'checks':checks,'snapshots':evidence,'browser_age_control':'browser clock advanced 10 minutes; stored ACK unchanged','config_sha256':{'console':hashlib.sha256((cd/'firewall.yaml').read_bytes()).hexdigest(),'agent':hashlib.sha256((home/'.agentfw/config.yaml').read_bytes()).hexdigest()},'binary_sha256':{p.name:hashlib.sha256(p.read_bytes()).hexdigest() for p in [console_binary,agent_binary]}}
        (args.output/'report.json').write_text(json.dumps(report,indent=2)+'\n',encoding='utf-8')
if __name__=='__main__':main()
