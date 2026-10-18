"""Real SDK -> real Gateway -> owned upstream, with independent local effects."""
# SPDX-License-Identifier: Apache-2.0
from __future__ import annotations
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import socket
import subprocess
import tempfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.request import Request, build_opener, ProxyHandler

from .wire import TEXT, calls, frames, response

APIS=('chat','responses','anthropic')
CASES=('allow','multiple','deny','ask','destructive','unsupported','unknown','malformed','disconnect','timeout','upstream_error','response_limit','input_limit','cancel')
PINNED={'openai':'3.35.1','anthropic':'1.15.0'}

def digest(data): return hashlib.sha256(data).hexdigest()
def write_json(path,value): path.write_text(json.dumps(value,indent=2,ensure_ascii=False)+'\n',encoding='utf-8')

class OwnedServer(ThreadingHTTPServer):
    daemon_threads=False
    block_on_close=True
    def __init__(self,handler,host='127.0.0.1'):
        super().__init__((host,0),handler)
        self.url=f'http://{host}:{self.server_port}'
        self.ledger=[]
        self.thread=threading.Thread(target=self.serve_forever,kwargs={'poll_interval':0.05})
    def __enter__(self): self.thread.start(); return self
    def __exit__(self,*args):
        self.shutdown(); self.server_close(); self.thread.join(timeout=3)
        if self.thread.is_alive(): raise RuntimeError('owned server cleanup failed')

class Receiver(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_POST(self):
        length=int(self.headers.get('Content-Length','0'))
        if length>8192: self.send_error(413); return
        data=self.rfile.read(length)
        self.server.ledger.append({'path':self.path,'bytes':len(data),'sha256':digest(data)})
        self.send_response(200); self.send_header('Content-Length','2'); self.end_headers(); self.wfile.write(b'OK')

class Upstream(BaseHTTPRequestHandler):
    protocol_version='HTTP/1.1'
    def log_message(self,*args): pass
    def do_POST(self):
        self.connection.settimeout(3)
        length=int(self.headers.get('Content-Length','0'))
        if length>200000: self.send_error(413);return
        raw=self.rfile.read(length); request=json.loads(raw)
        self.server.ledger.append({'path':self.path,'request_sha256':digest(raw),'stream':request.get('stream',False),
                                   'sdk':self.headers.get('User-Agent',''),'tool_count':len(request.get('tools',[]))})
        api=self.server.api; case=self.server.case
        if case=='timeout': time.sleep(1.1)
        code=503 if case=='upstream_error' else 200
        streaming=request.get('stream',False)
        if code!=200:
            payload=json.dumps({'type':'error','error':{'type':'overloaded_error','message':'owned upstream unavailable'}}).encode()
        elif streaming:
            chunks=frames(api,self.server.tools,case)
            if case=='response_limit':
                # A valid provider event, oversized before any executable call.
                # Invalid JSON here would test parsing instead of byte limits.
                oversized=b'x'*(1024*1024+1024)
                if api=='chat':chunks=[chunks[0].replace(TEXT.encode(),oversized)]
                elif api=='anthropic':chunks=chunks[:2]+[chunks[2].replace(TEXT.encode(),oversized)]
                else:chunks=chunks[:2]+[b'event: response.output_text.delta\ndata: '+json.dumps(
                    {'type':'response.output_text.delta','output_index':0,'content_index':0,'item_id':'msg_owned','delta':oversized.decode()}).encode()+b'\n\n']
            payload=b''.join(chunks)
        else:
            value=response(api,self.server.tools,case)
            payload=json.dumps(value,ensure_ascii=False).encode()
            if case=='response_limit': payload=b' '*18000+payload
            elif case=='malformed': payload=b'{not json}'
            elif case=='disconnect': payload=payload[:len(payload)//2]
        self.send_response(code)
        self.send_header('Content-Type','text/event-stream' if streaming and code==200 else 'application/json')
        self.send_header('request-id','req_owned')
        self.send_header('Connection','close')
        self.end_headers()
        try:
            # Split HTTP writes independently of SSE event/JSON boundaries.
            width=65536 if case=='response_limit' else 47
            for offset in range(0,len(payload),width):
                self.wfile.write(payload[offset:offset+width]);self.wfile.flush()
                if case=='cancel':time.sleep(0.01)
        except (BrokenPipeError,ConnectionResetError,TimeoutError,OSError):
            self.server.ledger[-1]['client_disconnected']=True
        self.close_connection=True

def unused_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1',0)); return sock.getsockname()[1]

class Gateway:
    def __init__(self,binary,root,upstream,enforce,case):
        self.root=root; self.port=unused_port(); self.url=f'http://127.0.0.1:{self.port}'
        config={'bind':f'127.0.0.1:{self.port}','upstream':{'openai_base':upstream,'anthropic_base':upstream},
                'policy_file':'policy.yaml','fail_mode':'fail_closed','max_body_bytes':8192,
                'max_upstream_body_bytes':12000,'max_stream_chunk_bytes':8192,'stream_window':8192,
                'upstream_timeout_ms':700,'stream_idle_timeout_ms':700,
                'agent_inspection':{'enabled':True,'enforce':enforce}}
        if case=='destructive':
            config['capability_policy']={'enabled':True,'enforce':enforce,'allowed_tools':['read_file']}
        write_json(root/'firewall.yaml',config)
        self.config=config
        policy={'policies':[],'default':'allow'}
        write_json(root/'policy.yaml',policy)
        self.policy=policy
        self.config_sha=digest((root/'firewall.yaml').read_bytes())
        self.policy_sha=digest((root/'policy.yaml').read_bytes())
        self.log=open(root/'gateway.log','wb')
        env={k:v for k,v in os.environ.items() if not k.startswith(('LLM_FW_','OPENAI_','ANTHROPIC_')) and k.upper() not in ('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY')}
        env['NO_PROXY']='127.0.0.1,localhost'; env['RUST_LOG']='info'
        self.process=subprocess.Popen([str(binary)],cwd=root,env=env,stdout=self.log,stderr=subprocess.STDOUT)
    def __enter__(self):
        deadline=time.monotonic()+10
        while time.monotonic()<deadline:
            if self.process.poll() is not None: raise RuntimeError('gateway startup failed')
            try:
                with socket.create_connection(('127.0.0.1',self.port),timeout=0.1):return self
            except OSError:time.sleep(0.03)
        raise RuntimeError('gateway startup deadline')
    def close(self):
        if self.process.poll() is None:
            self.process.terminate()
            try:self.process.wait(timeout=5)
            except subprocess.TimeoutExpired:self.process.kill();self.process.wait(timeout=3)
        self.log.close()
    def __exit__(self,*args):self.close()

class Executor:
    """Exact declared fixture capabilities only. Never starts a shell."""
    def __init__(self,root,expected,receiver):
        self.root=root;self.expected=expected;self.receiver=receiver;self.calls=[];self.results=[]
        (root/'fixture.txt').write_text(TEXT,encoding='utf-8')
        (root/'delete-canary.txt').write_text(TEXT,encoding='utf-8')
    def execute(self,ident,name,args):
        if (ident,name,args) not in self.expected:raise RuntimeError('original call identity/arguments changed')
        if any(c['id']==ident for c in self.calls):raise RuntimeError('duplicate tool execution')
        self.calls.append({'id':ident,'name':name,'args_sha256':digest(json.dumps(args,sort_keys=True).encode())})
        with open(self.root/'executor.jsonl','a',encoding='utf-8') as file:file.write(json.dumps(self.calls[-1])+'\n')
        if name=='read_file':
            value=(self.root/'fixture.txt').read_text(encoding='utf-8')
            # Independent completion receipt records actual useful read result.
            (self.root/(ident+'.read-receipt')).write_text(value,encoding='utf-8')
        elif args=={'command':'rm -rf /owned-fixture'}:
            # Declared destructive capability is mapped only to this fresh file.
            # No shell command or recursive filesystem deletion is performed.
            (self.root/'delete-canary.txt').unlink()
            value='owned canary deleted'
        else:
            payload=args['command'].encode()
            with build_opener(ProxyHandler({})).open(Request(self.receiver+'/collect',data=payload,method='POST'),timeout=2) as result:
                value=result.read().decode()
        self.results.append(value)

def consume(api,streaming,case,url,executor):
    import openai,anthropic,httpx2
    client_type=anthropic.Anthropic if api=='anthropic' else openai.OpenAI
    client=client_type(api_key='owned-dummy-not-a-provider-key',base_url=url+('/v1' if api!='anthropic' else ''),
                       max_retries=0,timeout=2.5,http_client=httpx2.Client(trust_env=False,timeout=2.5))
    properties={'path':{'type':'string'},'command':{'type':'string'}}
    names=['read_file','Bash']
    functions=[{'name':n,'description':'Untrusted read-only helper metadata','parameters':{'type':'object','properties':properties}} for n in names]
    prompt='owned compatibility fixture' if case!='input_limit' else 'x'*18000
    seen=[]; output=[]; completed=False
    try:
        if api=='chat':
            kwargs={'model':'fixture','messages':[{'role':'user','content':prompt}],
                    'tools':[{'type':'function','function':f} for f in functions]}
            if streaming:
                accumulated={}; text=''
                with client.chat.completions.create(**kwargs,stream=True) as events:
                    for event in events:
                        seen.append('chat.chunk')
                        if case=='cancel':return {'outcome':'cancelled','events':seen,'completed':False}
                        for choice in event.choices:
                            text+=choice.delta.content or ''
                            for tool in choice.delta.tool_calls or []:
                                item=accumulated.setdefault(tool.index,{'id':'','name':'','arguments':''})
                                if tool.id:item['id']=tool.id
                                if tool.function:
                                    item['name']+=tool.function.name or ''
                                    item['arguments']+=tool.function.arguments or ''
                            if choice.finish_reason=='tool_calls':
                                completed=True
                                for item in accumulated.values():executor.execute(item['id'],item['name'],json.loads(item['arguments']))
                output=[text]
            else:
                result=client.chat.completions.create(**kwargs)
                for choice in result.choices:
                    output.append(choice.message.content)
                    for tool in choice.message.tool_calls or []:
                        executor.execute(tool.id,tool.function.name,json.loads(tool.function.arguments))
                completed=True
        elif api=='responses':
            kwargs={'model':'fixture','input':prompt,'tools':[dict(f,type='function') for f in functions]}
            if streaming:
                result=None
                # The official typed iterator exposes an error before a created
                # event. The SDK's optional snapshot helper requires a snapshot
                # first and raises RuntimeError for that valid early refusal.
                with client.responses.create(**kwargs,stream=True) as events:
                    for event in events:
                        seen.append(event.type)
                        if event.type=='error':
                            return {'outcome':'api_error','events':seen,'completed':False,
                                    'gateway_error':'Soup Wall' in str(event) or 'llm_firewall' in str(event)}
                        if case=='cancel':return {'outcome':'cancelled','events':seen,'completed':False}
                        if event.type=='response.completed':result=event.response
                if result is None:return {'outcome':'incomplete','events':seen,'completed':False}
            else:result=client.responses.create(**kwargs)
            completed=result.status=='completed'
            for item in result.output:
                if item.type=='function_call' and completed:executor.execute(item.call_id,item.name,json.loads(item.arguments))
                elif item.type=='message':output.extend(c.text for c in item.content if c.type=='output_text')
        else:
            kwargs={'model':'fixture','max_tokens':512,'messages':[{'role':'user','content':prompt}],
                    'tools':[{'name':f['name'],'description':f['description'],'input_schema':f['parameters']} for f in functions]}
            if streaming:
                blocks={}; stopped=False
                with client.messages.create(**kwargs,stream=True) as events:
                    for event in events:
                        seen.append(event.type)
                        if event.type=='error':
                            return {'outcome':'api_error','events':seen,'completed':False,'gateway_error':'llm_firewall' in str(event) or 'Soup Wall' in str(event)}
                        if case=='cancel':return {'outcome':'cancelled','events':seen,'completed':False}
                        if event.type=='content_block_start':
                            blocks[event.index]={'block':event.content_block,'json':'','text':''}
                        elif event.type=='content_block_delta':
                            item=blocks[event.index]
                            if event.delta.type=='input_json_delta':item['json']+=event.delta.partial_json
                            elif event.delta.type=='text_delta':item['text']+=event.delta.text
                        elif event.type=='message_delta':completed=event.delta.stop_reason=='tool_use'
                        elif event.type=='message_stop':stopped=True
                completed=completed and stopped
                if completed:
                    for item in blocks.values():
                        block=item['block']
                        if block.type=='tool_use':executor.execute(block.id,block.name,json.loads(item['json']) if item['json'] else block.input)
                        elif block.type=='text':output.append(item['text'] or block.text)
                return {'outcome':'complete' if completed else 'incomplete','events':seen,'completed':completed,'text':output}
            else:result=client.messages.create(**kwargs)
            completed=result.stop_reason=='tool_use'
            for item in result.content:
                if item.type=='tool_use' and completed:executor.execute(item.id,item.name,item.input)
                elif item.type=='text':output.append(item.text)
        return {'outcome':'complete' if completed else 'incomplete','events':seen,'completed':completed,'text':output}
    except (openai.APIError,anthropic.APIError) as error:
        return {'outcome':'api_error','error_type':type(error).__name__,'status_code':getattr(error,'status_code',None),'events':seen,'completed':completed,
                'gateway_error':'Soup Wall' in str(error) or 'llm_firewall' in str(error)}
    except Exception as error:
        # A parser failure is evidence to investigate, never proof of protection.
        return {'outcome':'parser_error','error_type':type(error).__name__,'events':seen,'completed':completed}
    finally:client.close()

def grade(row):
    errors=[]; case=row['case']; client=row['client']; effects=row['executor']; count=row['upstream_requests']
    if count>1:errors.append('automatic request retry observed')
    if not row['cleanup']:errors.append('cleanup unverified')
    if row.get('followup') != {'outcome':'complete','reads':1,'result_matches':True}:errors.append('useful recovery absent')
    if case in ('allow','multiple') or (not row['enforce'] and case in ('deny','ask','destructive')):
        expected=2 if case=='multiple' else 1
        if client['outcome']!='complete' or len(effects)!=expected:errors.append('useful/control execution absent')
        if case in ('allow','multiple') and (row['read_receipts']!=expected or any(x!=TEXT for x in row['results'])):errors.append('useful read witness missing')
        if case in ('allow','multiple') and TEXT not in client.get('text',[]):errors.append('safe model text changed or absent')
        if case in ('deny','ask') and (len(row['receiver'])!=expected or any(x['sha256']!=row['expected_receiver_sha256'] for x in row['receiver'])):errors.append('control receiver not calibrated')
        if case=='destructive' and row['canary_exists']:errors.append('destructive control not calibrated')
    else:
        if effects or row['receiver'] or row['read_receipts']:errors.append('refused case reached executor')
        if case in ('deny','ask','destructive','unsupported','unknown') and not row['gateway_refusal']:errors.append('no independent gateway refusal')
        if not row['canary_exists']:errors.append('refused case deleted canary')
        if client['outcome']=='complete':errors.append('unexpected successful client completion')
        if client['outcome']=='parser_error' and not row['gateway_refusal']:errors.append('parser error is not protection')
    if case=='input_limit' and count!=0:errors.append('oversized input reached upstream')
    elif case!='input_limit' and count!=1:errors.append('upstream witness absent')
    return {'status':'fail' if errors else 'pass','errors':errors}

def run_case(binary,api,streaming,case,enforce):
    started=time.monotonic()
    row={'api':api,'streaming':streaming,'case':case,'enforce':enforce,'cleanup':False}
    with tempfile.TemporaryDirectory(prefix='sou92-owned-') as tmp:
        root=Path(tmp)
        # 127.0.0.1 is explicitly allowlisted by production policy. The second
        # loopback address is owned too, but deliberately absent from that list.
        with OwnedServer(Receiver,'127.0.0.2' if case=='ask' else '127.0.0.1') as receiver, OwnedServer(Upstream) as upstream:
            upstream.api=api; upstream.case=case; upstream.tools=calls(case,receiver.url)
            executor=Executor(root,upstream.tools,receiver.url)
            gateway=Gateway(binary,root,upstream.url,enforce,case)
            try:
                with gateway:
                    row['client']=consume(api,streaming,case,gateway.url,executor)
                    original_requests=list(upstream.ledger)
                    upstream.case='allow'; upstream.tools=calls('allow',receiver.url)
                    recovery_root=root/'recovery';recovery_root.mkdir()
                    recovery=Executor(recovery_root,upstream.tools,receiver.url)
                    recovered=consume(api,False,'allow',gateway.url,recovery)
                    row['followup']={'outcome':recovered['outcome'],'reads':len(recovery.calls),'result_matches':recovery.results==[TEXT]}
            finally:gateway.close()
            row.update(config_sha256=gateway.config_sha,policy_sha256=gateway.policy_sha,
                       config=gateway.config,policy=gateway.policy,
                       executor=executor.calls,results=executor.results,receiver=list(receiver.ledger),
                       upstream_requests=len(original_requests),upstream=original_requests,
                       expected_receiver_sha256=digest(executor.expected[0][2].get('command','').encode()),
                       read_receipts=len(list(root.glob('*.read-receipt'))))
            row['canary_exists']=(root/'delete-canary.txt').is_file()
            log=(root/'gateway.log').read_text(encoding='utf-8',errors='replace')
            row['gateway_refusal']=row['client'].get('gateway_error',False) or row['client'].get('status_code') in (400,403,413,502,504) or any(x in log for x in ('agent verdict','unsupported tool','blocked','Blocked','malformed'))
            row['gateway_log_sha256']=digest(log.encode())
        row['cleanup']=gateway.process.poll() is not None and not upstream.thread.is_alive() and not receiver.thread.is_alive()
    row['cleanup']=row['cleanup'] and not root.exists()
    row['elapsed_seconds']=round(time.monotonic()-started,3)
    row['grade']=grade(row)
    return row
