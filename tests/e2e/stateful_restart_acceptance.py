#!/usr/bin/env python3
"""Isolated platform restart acceptance with actual GmSSL engine; never stops shared services."""
import argparse, base64, glob, json, os, pathlib, secrets, socket, subprocess, time, uuid
from http_acceptance import Client, CheckFailure

ROOT=pathlib.Path(__file__).resolve().parents[2]
MARKER_SOURCE='''import java.sql.*;
public class MarkPending {
 public static void main(String[] ignored) throws Exception {
  if (!"1".equals(System.getenv("REVIEW_ISOLATED_INSTANCE"))) throw new IllegalStateException();
  Class.forName("org.h2.Driver");
  try (var c=DriverManager.getConnection(System.getenv("SPRING_DATASOURCE_URL"),System.getenv("SPRING_DATASOURCE_USERNAME"),System.getenv("SPRING_DATASOURCE_PASSWORD"))) {
   try(var p=c.prepareStatement("update materials set pending=true where id=? and key_kind='STATEFUL_PRIVATE_KEY'")) {
    p.setString(1,System.getenv("REVIEW_KEY_ID")); if(p.executeUpdate()!=1)throw new IllegalStateException("Isolated stateful key missing");
   }
   try(var p=c.prepareStatement("update jobs set status='RUNNING' where id=?")) {
    p.setString(1,System.getenv("REVIEW_JOB_ID")); if(p.executeUpdate()!=1)throw new IllegalStateException("Isolated job missing");
   }
  }
 }
}
'''

def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('--engine-url',default='http://127.0.0.1:8081')
    ap.add_argument('--jar',default=str(ROOT/'platform-service/target/platform-service-0.1.0-SNAPSHOT.jar'))
    ap.add_argument('--java',default=os.environ.get('JAVA_HOME','')+'/bin/java')
    args=ap.parse_args()
    if not os.environ.get('GMSSL_ENGINE_TOKEN'):ap.error('set GMSSL_ENGINE_TOKEN via private environment')
    target=ROOT/'tests/e2e/results'/('restart_'+uuid.uuid4().hex[:10]);target.mkdir(parents=True,mode=0o700)
    os.chmod(target,0o700)
    with socket.socket() as sock:sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    env=dict(os.environ)
    env.update({'SERVER_ADDRESS':'127.0.0.1','SERVER_PORT':str(port),'GMSSL_BOOTSTRAP_USERNAME':'restart_admin','GMSSL_BOOTSTRAP_PASSWORD':secrets.token_hex(20),'GMSSL_VAULT_MASTER_KEY':base64.b64encode(secrets.token_bytes(32)).decode(),'GMSSL_VAULT_DIR':str(target/'vault'),'GMSSL_ENGINE_URL':args.engine_url,'SPRING_DATASOURCE_URL':'jdbc:h2:file:'+str(target/'db')+';MODE=PostgreSQL;DATABASE_TO_LOWER=TRUE;DEFAULT_NULL_ORDERING=HIGH','SPRING_DATASOURCE_USERNAME':'review','SPRING_DATASOURCE_PASSWORD':secrets.token_hex(20),'REVIEW_ISOLATED_INSTANCE':'1'})
    proc=None; log=None; rows=[]
    def start(suffix):
        nonlocal proc,log
        log=open(target/('platform_'+suffix+'.log'),'wb')
        proc=subprocess.Popen([args.java,'-jar',str(pathlib.Path(args.jar).resolve())],env=env,cwd=ROOT,stdout=log,stderr=subprocess.STDOUT)
        end=time.monotonic()+75
        while time.monotonic()<end:
            if proc.poll() is not None:raise CheckFailure('isolated platform failed startup; inspect private log')
            try:
                import urllib.request
                with urllib.request.urlopen('http://127.0.0.1:'+str(port)+'/actuator/health',timeout=1) as r:
                    if r.status==200:return
            except Exception:pass
            time.sleep(.3)
        raise CheckFailure('isolated readiness timeout')
    def stop():
        nonlocal proc,log
        if proc is not None and proc.poll() is None:
            proc.terminate()
            try:proc.wait(timeout=12)
            except subprocess.TimeoutExpired:proc.kill();proc.wait(timeout=5)
        if log:log.close()
    client=Client('http://127.0.0.1:'+str(port))
    def job(pid,tool,params,terminal='SUCCEEDED'):
        j=client.expect('POST','/projects/'+pid+'/jobs',{'toolId':tool,'parameters':params,'stdinText':'pending-restart-message','timeoutSeconds':30},codes=(202,))
        end=time.monotonic()+45
        while j['status'] in ('QUEUED','RUNNING') and time.monotonic()<end:
            time.sleep(.2);j=client.expect('GET','/projects/'+pid+'/jobs/'+j['id'])
        if j['status']!=terminal:raise CheckFailure(tool+' terminal '+j['status']+' != '+terminal)
        return j
    try:
        start('before');client.login(env['GMSSL_BOOTSTRAP_USERNAME'],env['GMSSL_BOOTSTRAP_PASSWORD'])
        pid=client.expect('POST','/projects',{'name':'isolated-pending-restart'})['id']
        # keygen rejects stdin, use dedicated submission.
        g=client.expect('POST','/projects/'+pid+'/jobs',{'toolId':'lmskeygen','parameters':{'lms_type':'LMS_SM3_M32_H5','out':'managed.key','pubout':'public.key'}},codes=(202,))
        end=time.monotonic()+45
        while g['status'] in ('QUEUED','RUNNING') and time.monotonic()<end:
            time.sleep(.2);g=client.expect('GET','/projects/'+pid+'/jobs/'+g['id'])
        if g['status']!='SUCCEEDED':raise CheckFailure('actual stateful keygen failed '+g['status'])
        art=next(a for a in g['artifacts'] if a['name']=='managed.key')
        key=client.expect('POST','/projects/'+pid+'/jobs/'+g['id']+'/artifacts/'+art['id']+'/save-key',{'name':'single authority','algorithm':'LMS','keyKind':'STATEFUL_PRIVATE_KEY'},codes=(200,201))
        signed=job(pid,'lmssign',{'key':'key:'+key['id'],'out':'before.sig'})
        rows.append({'id':'STATE-live-baseline','status':'PASS','detail':'real LMS H5 generation, controlled promotion and signing succeeded'})
        stop()
        helpers=target/'MarkPending.java';helpers.write_text(MARKER_SOURCE)
        h2=sorted((ROOT/'.tools/m2/repository/com/h2database/h2').glob('*/h2-*.jar'))
        if not h2:raise CheckFailure('isolated H2 driver not found')
        env['REVIEW_KEY_ID']=key['id'];env['REVIEW_JOB_ID']=signed['id']
        # Child process receives passwords only via env; stdout never includes a JDBC URL/password.
        mark=subprocess.run([args.java,'-cp',str(h2[-1]),str(helpers)],env=env,cwd=target,capture_output=True,timeout=30)
        if mark.returncode:raise CheckFailure('isolated pending injection failed; exit '+str(mark.returncode))
        start('after');client=Client('http://127.0.0.1:'+str(port));client.login(env['GMSSL_BOOTSTRAP_USERNAME'],env['GMSSL_BOOTSTRAP_PASSWORD'])
        old=client.expect('GET','/projects/'+pid+'/jobs/'+signed['id'])
        if old['status']!='FAILED':raise CheckFailure('RUNNING job not recovered as FAILED')
        rows.append({'id':'STATE-recover-running','status':'PASS','detail':'restart marked prior RUNNING job FAILED'})
        rejected=job(pid,'lmssign',{'key':'key:'+key['id'],'out':'after.sig'},terminal='FAILED')
        if rejected.get('artifacts'):raise CheckFailure('pending key released signing artifact')
        if not any(word in str(rejected.get('error','')).lower() for word in ('pending','recovery','busy')):raise CheckFailure('pending rejection diagnostic not explicit')
        rows.append({'id':'STATE-pending-restart-block','status':'PASS','detail':'pending persisted across restart and prevented another signature artifact'})
    except Exception as e:
        rows.append({'id':'STATE-isolated-restart','status':'FAIL','detail':type(e).__name__+': '+str(e)[:300]})
    finally:stop()
    counts={s:sum(r['status']==s for r in rows) for s in ('PASS','FAIL')}
    (target/'report.json').write_text(json.dumps({'counts':counts,'results':rows,'scope':'controlled pending injection into own isolated H2; not physical power-loss proof','sharedServicesStopped':False},indent=2)+'\n')
    print('REPORT',target,'COUNTS',counts)
    for row in rows:print(row)
    return bool(counts['FAIL'])
if __name__=='__main__':raise SystemExit(main())
