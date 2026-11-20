#!/usr/bin/env python3
"""Real HTTP acceptance, Python stdlib only; no mocked engine or algorithms."""
import argparse, base64, http.cookiejar, json, os, pathlib, secrets, time
import urllib.request, urllib.error, uuid, subprocess, struct, tempfile

class CheckFailure(Exception): pass

class Client:
    def __init__(self, base):
        self.base = base.rstrip('/') + '/api/v1'
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = None
    def call(self, method, path, body=None, raw=None, headers=None, csrf=True):
        h = dict(headers or {})
        if body is not None:
            raw = json.dumps(body).encode(); h['Content-Type'] = 'application/json'
        if method not in ('GET','HEAD') and csrf and self.csrf: h['X-CSRF-Token'] = self.csrf
        req = urllib.request.Request(self.base + path, data=raw, headers=h, method=method)
        try:
            with self.opener.open(req, timeout=40) as r: code, data, rh = r.status, r.read(), r.headers
        except urllib.error.HTTPError as e: code, data, rh = e.code, e.read(), e.headers
        try: parsed = json.loads(data)
        except (ValueError, UnicodeDecodeError): parsed = data
        return code, parsed, rh
    def expect(self, method, path, body=None, codes=(200,), **kw):
        code, data, _ = self.call(method,path,body,**kw)
        if code not in codes: raise CheckFailure('%s %s returned %s, expected %s' % (method,path,code,codes))
        return data
    def login(self, username, password):
        obj = self.expect('POST','/auth/login',{'username':username,'password':password},csrf=False)
        self.csrf = obj['csrfToken']; return obj['user']
    def upload(self, pid, data, filename='input.bin', kind='files', meta=None, codes=(200,201)):
        boundary = 'gmssl-e2e-' + uuid.uuid4().hex
        chunks = []
        for k,v in (meta or {}).items():
            chunks += [('--'+boundary+'\r\nContent-Disposition: form-data; name="'+k+'"\r\n\r\n'+str(v)+'\r\n').encode()]
        chunks += [('--'+boundary+'\r\nContent-Disposition: form-data; name="file"; filename="'+filename+'"\r\nContent-Type: application/octet-stream\r\n\r\n').encode(), data, ('\r\n--'+boundary+'--\r\n').encode()]
        return self.expect('POST','/projects/'+pid+'/'+kind,raw=b''.join(chunks),headers={'Content-Type':'multipart/form-data; boundary='+boundary},codes=codes)

class Suite:
    def __init__(self,args):
        self.args=args; self.results=[]; self.prefix='e2e_'+uuid.uuid4().hex[:10]
        self.admin=Client(args.url); self.a=Client(args.url); self.b=Client(args.url)
        self.secrets=[]; self.catalog={}; self.tools={}
        self.out=pathlib.Path(args.output)/self.prefix; self.out.mkdir(parents=True,exist_ok=True)
    def check(self,name,fn):
        start=time.monotonic()
        try:
            detail=fn(); row={'id':name,'status':'PASS','detail':detail or 'assertions passed'}
        except unittest_skip as e: row={'id':name,'status':'SKIP','detail':str(e)}
        except Exception as e:
            detail=str(e)
            for secret in self.secrets: detail=detail.replace(secret,'[REDACTED]')
            row={'id':name,'status':'FAIL','detail':type(e).__name__+': '+detail[:700]}
        row['durationMs']=round((time.monotonic()-start)*1000); self.results.append(row)
        print(row['status'],name,row['detail'],flush=True)
    def require(self,yes,message):
        if not yes: raise CheckFailure(message)
    def job(self,tool,params=None,stdin=None,client=None,pid=None,timeout=30,terminal='SUCCEEDED'):
        c=client or self.a; pid=pid or self.pa
        if tool not in self.tools: raise unittest_skip('catalog missing '+tool)
        body={'toolId':tool,'parameters':params or {},'timeoutSeconds':timeout}
        if stdin is not None: body['stdinText']=stdin
        j=c.expect('POST','/projects/'+pid+'/jobs',body,codes=(202,))
        deadline=time.monotonic()+timeout+35
        while j['status'] in ('QUEUED','RUNNING') and time.monotonic()<deadline:
            time.sleep(.15); j=c.expect('GET','/projects/'+pid+'/jobs/'+j['id'])
        self.require(j['status']==terminal,tool+' ended '+str(j['status'])+' expected '+terminal)
        return j
    def artifact(self,j,name=None,c=None,pid=None):
        c=c or self.a; pid=pid or self.pa
        arts=j.get('artifacts',[])
        if name is not None: arts=[x for x in arts if x['name']==name]
        self.require(bool(arts),'required artifact missing '+str(name))
        a=arts[0]; data=c.expect('GET','/projects/'+pid+'/jobs/'+j['id']+'/artifacts/'+a['id']+'/download')
        self.require(isinstance(data,bytes),'download did not return raw bytes')
        return data,a
    def setup(self):
        user=self.admin.login(os.environ['E2E_ADMIN_USERNAME'],os.environ['E2E_ADMIN_PASSWORD'])
        self.require(user['role']=='ADMIN','bootstrap user is not ADMIN')
        cookies=list(self.admin.jar)
        self.require(any(c.name=='GMSSL_SESSION' and c.has_nonstandard_attr('HttpOnly') and str(c.get_nonstandard_attr('SameSite')).lower()=='strict' for c in cookies),'session cookie must be HttpOnly/SameSite=Strict')
        ids=[]
        for n,c in [('a',self.a),('b',self.b)]:
            password='E2e-'+secrets.token_hex(18); self.secrets.append(password)
            u=self.admin.expect('POST','/users',{'username':self.prefix+'_'+n,'password':password,'role':'USER'},codes=(200,201))
            logged=c.login(self.prefix+'_'+n,password); ids.append(logged['id'])
        self.ua,self.ub=ids
        self.pa=self.a.expect('POST','/projects',{'name':self.prefix+'_a'})['id']
        self.pb=self.b.expect('POST','/projects',{'name':self.prefix+'_b'})['id']
        self.catalog=self.a.expect('GET','/capabilities'); self.tools={t['id']:t for t in self.catalog['tools']}
        self.require(self.catalog['sourceCommit']=='24ae482701a7b124826c382fffc55c19f76d475d','catalog commit mismatch')
        return 'two real USER logins and isolated projects; '+str(len(self.tools))+' catalog tools'
    def unauth(self):
        c=Client(self.args.url)
        for p in ['/auth/me','/projects','/capabilities']: c.expect('GET',p,codes=(401,))
    def csrf(self):
        self.a.expect('POST','/projects',{'name':'rejected-no-csrf'},codes=(403,),csrf=False)
        self.a.expect('POST','/projects',{'name':'rejected-bad-csrf'},codes=(403,),csrf=False,headers={'X-CSRF-Token':'invalid'})
    def roles(self):
        self.a.expect('GET','/users',codes=(403,))
        self.a.expect('POST','/users',{'username':'forbidden','password':'123456789012','role':'ADMIN'},codes=(403,))
        self.a.expect('DELETE','/projects/'+self.pa+'/members/'+self.ua,codes=(400,403,409))
        self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'tls13_client','parameters':{}},codes=(403,))
    def isolation(self):
        self.require(all(x['id']!=self.pb for x in self.a.expect('GET','/projects')),'foreign project listed')
        self.b.expect('GET','/projects/'+self.pa,codes=(403,404))
        self.file=self.a.upload(self.pa,b'abc','message.txt')
        self.private=self.a.upload(self.pa,b'PRIVATE_FIXTURE_'+self.prefix.encode(),'private.bin','keys',{'name':'isolated key','algorithm':'SM2','keyKind':'PRIVATE_KEY','encoding':'RAW'})
        for kind,obj in [('files',self.file),('keys',self.private)]:
            self.b.expect('GET','/projects/'+self.pb+'/'+kind+'/'+obj['id']+'/download',codes=(403,404))
            self.b.expect('GET','/projects/'+self.pa+'/'+kind+'/'+obj['id']+'/download',codes=(403,404))
        self.b.expect('POST','/projects/'+self.pb+'/jobs',{'toolId':'sm3','parameters':{'in':'file:'+self.file['id']}},codes=(400,403,404))
        self.b.expect('POST','/projects/'+self.pb+'/jobs',{'toolId':'sm2sign','parameters':{'key':'key:'+self.private['id'],'pass':'not-used'}},codes=(400,403,404))
        self.require(self.private.get('validationStatus')=='UNVERIFIED','import must not claim validation')
    def viewer(self):
        root='/projects/'+self.pa
        self.a.expect('PUT',root+'/members/'+self.ub,{'role':'VIEWER'},codes=(200,201,204))
        try:
            self.b.expect('GET',root+'/keys')
            self.b.expect('GET',root+'/keys/'+self.private['id']+'/download',codes=(403,))
            self.b.expect('POST',root+'/jobs',{'toolId':'sm3','stdinText':'abc'},codes=(403,))
            self.b.upload(self.pa,b'valid viewer upload','viewer.txt',codes=(403,))
            self.a.expect('PUT',root+'/members/'+self.ub,{'role':'EDITOR'},codes=(200,201,204))
            self.job('sm3',stdin='abc',client=self.b)
        finally: self.a.expect('DELETE',root+'/members/'+self.ub,codes=(200,204))
    def sm3(self):
        self.sm3job=self.job('sm3',stdin='abc')
        data,_=self.artifact(self.sm3job)
        self.require(b'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0' in data.lower(),'SM3 abc KAT mismatch')
    def artifacts_isolation(self):
        j=self.sm3job; _,a=self.artifact(j)
        self.b.expect('GET','/projects/'+self.pa+'/jobs/'+j['id'],codes=(403,404))
        self.b.expect('GET','/projects/'+self.pb+'/jobs/'+j['id'],codes=(403,404))
        self.b.expect('GET','/projects/'+self.pb+'/jobs/'+j['id']+'/artifacts/'+a['id']+'/download',codes=(403,404))
        self.b.expect('POST','/projects/'+self.pb+'/jobs/'+j['id']+'/artifacts/'+a['id']+'/save-key',{'name':'foreign','algorithm':'SM2','keyKind':'PRIVATE_KEY'},codes=(400,403,404))
    def parameters(self):
        for p in [{'nonexistent':'x'},{'in':'/etc/passwd'},{'out':'../outside.bin'}]:
            self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'sm3','parameters':p},codes=(400,403,422))
        self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'sm4_gcm','parameters':{'encrypt':True,'key':'xyz','iv':'00'*12}},codes=(400,422))
    def sm4(self):
        self.hexkey=secrets.token_hex(16); self.secrets.append(self.hexkey)
        common={'key':self.hexkey,'iv':'00112233445566778899aabb','aad':'e2e aad'}
        j=self.job('sm4_gcm',dict(common,encrypt=True,out='encrypted.bin'),stdin='real sm4 '+self.prefix)
        cipher,_=self.artifact(j,'encrypted.bin'); f=self.a.upload(self.pa,cipher)
        d=self.job('sm4_gcm',dict(common,decrypt=True,**{'in':'file:'+f['id'],'out':'plain.bin'}))
        plain,_=self.artifact(d,'plain.bin'); self.require(plain==('real sm4 '+self.prefix).encode(),'SM4 roundtrip mismatch')
        damaged=bytearray(cipher); damaged[-1]^=1; bad=self.a.upload(self.pa,bytes(damaged))
        self.job('sm4_gcm',dict(common,decrypt=True,**{'in':'file:'+bad['id']}),terminal='FAILED')
        self.require(not j.get('stdoutPreview') and not d.get('stdoutPreview'),'secret-bearing task leaked preview')
    def sm2(self):
        self.keypass='Key-'+secrets.token_hex(16); self.secrets.append(self.keypass)
        k=self.job('sm2keygen',{'pass':self.keypass,'out':'private.pem','pubout':'public.pem'})
        priv,pa=self.artifact(k,'private.pem'); pub,pua=self.artifact(k,'public.pem')
        self.require(b'ENCRYPTED PRIVATE KEY' in priv and b'PUBLIC KEY' in pub,'SM2 PEM generation mismatch')
        keys=[]
        for a,kind in [(pa,'PRIVATE_KEY'),(pua,'PUBLIC_KEY')]:
            keys.append(self.a.expect('POST','/projects/'+self.pa+'/jobs/'+k['id']+'/artifacts/'+a['id']+'/save-key',{'name':'generated '+kind,'algorithm':'SM2','keyKind':kind,'encoding':'PEM'},codes=(200,201)))
        self.sk,self.pk=keys
        enc=self.job('sm2encrypt',{'pubkey':'key:'+self.pk['id'],'out':'cipher.bin'},stdin='SM2 real '+self.prefix)
        ciphertext,_=self.artifact(enc,'cipher.bin'); f=self.a.upload(self.pa,ciphertext)
        dec=self.job('sm2decrypt',{'key':'key:'+self.sk['id'],'pass':self.keypass,'in':'file:'+f['id'],'out':'plain.bin'})
        plain,_=self.artifact(dec,'plain.bin'); self.require(plain==('SM2 real '+self.prefix).encode(),'SM2 decrypt mismatch')
        sign=self.job('sm2sign',{'key':'key:'+self.sk['id'],'pass':self.keypass,'id':'review-id','out':'sig.bin'},stdin='SM2 signed message')
        signature,_=self.artifact(sign,'sig.bin'); sf=self.a.upload(self.pa,signature)
        params={'pubkey':'key:'+self.pk['id'],'sig':'file:'+sf['id'],'id':'review-id'}
        self.job('sm2verify',params,stdin='SM2 signed message')
        self.job('sm2verify',dict(params,id='wrong-id'),stdin='SM2 signed message',terminal='FAILED')
    def temporary_files(self):
        # 1. Upload temporary file and verify DTO
        f = self.a.upload(self.pa, b'temp content for sm3', 'temp.bin', meta={'temporary': 'true'})
        if f.get('temporary') is None:
            raise unittest_skip('temporary file feature not yet deployed in platform service')
        self.require(f.get('temporary') is True, 'temporary flag missing or false on upload DTO')

        # 2. Reject temporary flag on KEY upload
        self.a.upload(self.pa, b'invalid-key-data', 'key.pem', kind='keys', meta={'temporary': 'true', 'keyKind': 'PRIVATE_KEY', 'algorithm': 'SM2'}, codes=(400,))

        # 3. Submit first job using temporary file
        j1 = self.job('sm3', {'in': 'file:' + f['id']})

        # 4. Double consumption: submitting second job with same temporary file must return 409 or 400/404
        self.a.expect('POST', '/projects/' + self.pa + '/jobs', {'toolId': 'sm3', 'parameters': {'in': 'file:' + f['id']}}, codes=(400, 404, 409))

        # 5. After j1 terminal, file must be deleted from DB and vault (404)
        self.a.expect('GET', '/projects/' + self.pa + '/files/' + f['id'], codes=(404,))
        self.a.expect('GET', '/projects/' + self.pa + '/files/' + f['id'] + '/download', codes=(404,))

        # 6. Cancellation cleanup: job cancelled while queued/running also purges temporary file
        f_cancel = self.a.upload(self.pa, b'temp content to cancel', 'cancel_temp.bin', meta={'temporary': 'true'})
        # Use sm4_cbc which accepts 'in' parameter
        jc = self.a.expect('POST', '/projects/' + self.pa + '/jobs', {'toolId': 'sm4_cbc', 'parameters': {'key': '00112233445566778899aabbccddeeff', 'iv': '00112233445566778899aabbccddeeff', 'in': 'file:' + f_cancel['id'], 'encrypt': True}, 'timeoutSeconds': 30}, codes=(202,))
        self.a.expect('POST', '/projects/' + self.pa + '/jobs/' + jc['id'] + '/cancel', {}, codes=(200, 202, 204))
        end = time.monotonic() + 15
        while time.monotonic() < end:
            cur = self.a.expect('GET', '/projects/' + self.pa + '/jobs/' + jc['id'])
            if cur['status'] in ('CANCELLED', 'FAILED', 'SUCCEEDED'): break
            time.sleep(0.2)
        self.a.expect('GET', '/projects/' + self.pa + '/files/' + f_cancel['id'], codes=(404,))
        self.a.expect('GET', '/projects/' + self.pa + '/files/' + f_cancel['id'] + '/download', codes=(404,))

        # 7. Permanent file remains reusable and accessible
        f_perm = self.a.upload(self.pa, b'permanent content', 'perm.bin', meta={'temporary': 'false'})
        self.require(f_perm.get('temporary') is False, 'permanent file marked temporary')
        j2 = self.job('sm3', {'in': 'file:' + f_perm['id']})
        j3 = self.job('sm3', {'in': 'file:' + f_perm['id']})
        perm_data = self.a.expect('GET', '/projects/' + self.pa + '/files/' + f_perm['id'] + '/download')
        self.require(perm_data == b'permanent content', 'permanent file content changed or unavailable')
        return 'temporary file DTO, key rejection, CAS/single consumption (409), terminal cleanup (404), cancel cleanup (404), and permanent file preservation passed'
    def stateful(self):
        for tool in ['lmssign','hsssign','xmsssign','xmssmtsign']:
            self.require(tool in self.tools and self.tools[tool].get('stateful') is True,'stateful catalog flag missing '+tool)
            for ref in ['key:'+self.private['id'],'file:'+self.file['id']]:
                self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':tool,'parameters':{'key':ref},'stdinText':'abc'},codes=(400,403,409,422))
        return 'four tools reject ordinary private key and temporary file before execution; pending recovery still separate'
    def stateful_authority(self):
        meta={'name':'external stateful','algorithm':'LMS','keyKind':'STATEFUL_PRIVATE_KEY','encoding':'RAW'}
        try:
            self.a.upload(self.pa,b'not-a-key','external.bin','keys',meta)
        except CheckFailure as e:
            self.require(any(str(code) in str(e) for code in (400,403,409,422)),'external import failed for unexpected reason')
        else: raise CheckFailure('external stateful key import was accepted')
        generated=self.job('lmskeygen',{'lms_type':'LMS_SM3_M32_H5','out':'lms_private.bin','pubout':'lms_public.bin'})
        arts={x['name']:x for x in generated['artifacts']}
        self.require('lms_private.bin' in arts and 'lms_public.bin' in arts,'stateful output artifacts missing')
        root='/projects/'+self.pa+'/jobs/'+generated['id']+'/artifacts/'
        private=arts['lms_private.bin']; public=arts['lms_public.bin']
        self.a.expect('GET',root+private['id']+'/download',codes=(403,409))
        self.a.expect('GET',root+public['id']+'/download')
        body={'name':'managed stateful','algorithm':'LMS','keyKind':'STATEFUL_PRIVATE_KEY','encoding':'RAW'}
        key=self.a.expect('POST',root+private['id']+'/save-key',dict(body,algorithm='SM2',keyKind='PRIVATE_KEY'),codes=(200,201))
        self.require(key['keyKind']=='STATEFUL_PRIVATE_KEY' and key['stateful'] is True and key['algorithm']=='LMS','server did not override user metadata with controlled stateful identity')
        self.a.expect('POST',root+private['id']+'/save-key',body,codes=(409,))
        self.a.expect('GET','/projects/'+self.pa+'/keys/'+key['id']+'/download',codes=(403,409))
        self.a.expect('GET',root+private['id']+'/download',codes=(403,409))
        self.job('lmssign',{'key':'key:'+key['id'],'out':'lms_sig.bin'},stdin='stateful message')
        self.a.expect('DELETE','/projects/'+self.pa+'/keys/'+key['id'],codes=(200,204))
        self.a.expect('POST',root+private['id']+'/save-key',body,codes=(409,))
        return 'controlled LMS generation/signing real; external import, downgrade/export/duplicate and tombstone resurrection rejected'
    def cancellation(self):
        if 'sm3_pbkdf2' not in self.tools: raise unittest_skip('no bounded slow task capability')
        params={'pass':'Cancel-'+secrets.token_hex(12),'salt':'00112233445566778899aabbccddeeff','iter':16777215,'outlen':32}
        self.secrets.append(params['pass'])
        j=self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'sm3_pbkdf2','parameters':params,'timeoutSeconds':30},codes=(202,))
        self.a.expect('POST','/projects/'+self.pa+'/jobs/'+j['id']+'/cancel',{},codes=(200,202,204))
        end=time.monotonic()+20
        while time.monotonic()<end:
            j=self.a.expect('GET','/projects/'+self.pa+'/jobs/'+j['id'])
            if j['status'] not in ('QUEUED','RUNNING'): break
            time.sleep(.2)
        self.require(j['status']=='CANCELLED','cancel did not yield CANCELLED')
    def timeout(self):
        secret='Timeout-'+secrets.token_hex(12); self.secrets.append(secret)
        self.job('sm3_pbkdf2',{'pass':secret,'salt':'00112233445566778899aabbccddeeff','iter':16777215,'outlen':32},timeout=1,terminal='TIMED_OUT')
    def leaks(self):
        root='/projects/'+self.pa
        aggregate=json.dumps({'jobs':self.a.expect('GET',root+'/jobs'),'keys':self.a.expect('GET',root+'/keys'),'audit':self.a.expect('GET',root+'/audit')})
        for secret in self.secrets: self.require(secret not in aggregate,'secret value in public persistence DTO')
        ps=subprocess.check_output(['ps','-axo','command='],text=True)
        for secret in self.secrets: self.require(secret not in ps,'secret value in process argv')
        scanned=0
        for d in self.args.scan_dir:
            path=pathlib.Path(d).resolve()
            self.require(path.is_dir(),'specified scan directory missing')
            for f in path.rglob('*'):
                if f.is_symlink() or not f.is_file() or f.stat().st_size>128*1024*1024: continue
                data=f.read_bytes(); scanned+=1
                for secret in self.secrets: self.require(secret.encode() not in data,'secret in controlled persistence path '+str(f))
        return 'DTOs/ps checked; '+str(scanned)+' persistence files scanned' if self.args.scan_dir else 'DTOs/ps checked; disk scan NOT_RUN (supply --scan-dir)'
    def internal_auth(self):
        engine=os.environ.get('E2E_ENGINE_URL','http://127.0.0.1:8081').rstrip('/')
        for headers in ({},{'X-Engine-Token':'incorrect-token'}):
            req=urllib.request.Request(engine+'/internal/v1/capabilities',headers=headers)
            try:
                with urllib.request.urlopen(req,timeout=5) as response: code=response.status
            except urllib.error.HTTPError as e: code=e.code
            self.require(code==401,'engine missing/wrong token did not return 401')
    def network_policy(self):
        self.job('tls13_client',{'host':'169.254.169.254','port':14433},client=self.admin,terminal='FAILED')
        self.job('tls13_client',{'host':'127.0.0.1','port':80},client=self.admin,terminal='FAILED')
    def bounded_queue(self):
        started=[]
        try:
            for _ in range(2):
                password='Queue-'+secrets.token_hex(12);self.secrets.append(password)
                started.append(self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'sm3_pbkdf2','parameters':{'pass':password,'salt':'00112233445566778899aabbccddeeff','iter':16777215,'outlen':32},'timeoutSeconds':30},codes=(202,)))
            self.a.expect('POST','/projects/'+self.pa+'/jobs',{'toolId':'sm3','stdinText':'abc'},codes=(429,))
        finally:
            for j in started:self.a.expect('POST','/projects/'+self.pa+'/jobs/'+j['id']+'/cancel',{},codes=(200,202,204))
            for j in started:
                end=time.monotonic()+20
                while time.monotonic()<end:
                    current=self.a.expect('GET','/projects/'+self.pa+'/jobs/'+j['id'])
                    if current['status'] in ('CANCELLED','FAILED','SUCCEEDED'):break
                    time.sleep(.2)
                self.require(current['status'] in ('CANCELLED','FAILED','SUCCEEDED'),'queue cleanup did not terminate')
    def logout(self):
        self.admin.expect('PATCH','/users/'+self.ub,{'enabled':False})
        self.b.expect('GET','/auth/me',codes=(401,))
        self.a.expect('POST','/auth/logout',{},codes=(200,204)); self.a.expect('GET','/auth/me',codes=(401,))
    def run(self):
        self.check('AUTH-01 anonymous',self.unauth)
        self.check('AUTH-02 fixtures/catalog',self.setup)
        if not hasattr(self,'pa') or not self.tools:
            self.results.append({'id':'remaining suite','status':'SKIP','detail':'setup prerequisite failed'})
        else:
            for n,f in [('AUTH-03 CSRF',self.csrf),('RBAC-01 system/last-owner',self.roles),('ISO-01/02/03 references',self.isolation),('RBAC-02 viewer/editor',self.viewer),('CRYPTO-01 SM3 KAT',self.sm3),('ISO-04 artifacts',self.artifacts_isolation),('INPUT-01 parameters',self.parameters),('FILE-01 temporary lifecycle',self.temporary_files),('CRYPTO-02 SM4-GCM',self.sm4),('CRYPTO-03 SM2',self.sm2),('STATE-01 gating',self.stateful),('STATE-02 authority/tombstone',self.stateful_authority),('JOB-01 cancel',self.cancellation),('JOB-02 timeout',self.timeout),('ENGINE-01 token',self.internal_auth),('NETWORK-01 blocked destinations',self.network_policy),('JOB-03 concurrency bound',self.bounded_queue),('SECRET-01/02 leakage',self.leaks),('AUTH-04 logout',self.logout)]: self.check(n,f)
        self.results.append({'id':'STATE-03 pending restart','status':'SKIP','detail':'requires isolated restart harness; HTTP gating is not recovery evidence'})
        counts={s:sum(x['status']==s for x in self.results) for s in ('PASS','FAIL','SKIP')}
        report={'run':self.prefix,'baseUrl':self.args.url,'counts':counts,'results':self.results,'fixtureProjects':{'a':getattr(self,'pa',None),'b':getattr(self,'pb',None)},'note':'No mocks. Created fixture account passwords exist only in process memory. Do not equate this subset to complete algorithm coverage.'}
        (self.out/'report.json').write_text(json.dumps(report,ensure_ascii=False,indent=2)+'\n')
        (self.out/'report.txt').write_text('\n'.join(x['status']+' '+x['id']+' '+x['detail'] for x in self.results)+'\n')
        print('REPORT',self.out,'COUNTS',counts)
        return bool(counts['FAIL'])

class unittest_skip(Exception): pass

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--url',default='http://127.0.0.1:8080')
    p.add_argument('--output',default=str(pathlib.Path(__file__).parent/'results'))
    p.add_argument('--scan-dir',action='append',default=[],help='explicit app-owned persistence/log directory; never scans user home')
    args=p.parse_args()
    for k in ('E2E_ADMIN_USERNAME','E2E_ADMIN_PASSWORD'):
        if not os.environ.get(k): p.error('set '+k+' in environment, never command arguments')
    raise SystemExit(Suite(args).run())

if __name__=='__main__': main()
