#!/usr/bin/env python3
"""Real native runner protocol checks; only stdlib and a built gmssl-runner."""
import argparse, json, os, pathlib, struct, subprocess, time, uuid

def u32(n): return struct.pack('>I',n)
def frame(args,stdin=b''):
    args=[x.encode() if isinstance(x,str) else x for x in args]
    return b'GMRUN001'+u32(len(args))+u32(sum(map(len,args)))+b''.join(u32(len(x))+x for x in args)+stdin

def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--runner',default=str(pathlib.Path(__file__).resolve().parents[2]/'native/.build/bin/gmssl-runner'))
    p.add_argument('--output',default=str(pathlib.Path(__file__).parent/'results'))
    a=p.parse_args(); runner=str(pathlib.Path(a.runner).resolve()); rows=[]
    def check(name,fn):
        try: fn(); rows.append({'id':name,'status':'PASS'})
        except Exception as e: rows.append({'id':name,'status':'FAIL','detail':str(e)[:300]})
        print(rows[-1],flush=True)
    def invoke(data,argv=()): return subprocess.run([runner,*argv],input=data,capture_output=True,timeout=8)
    def invalid(data,argv=()):
        r=invoke(data,argv)
        assert r.returncode==64 and b'invalid execution frame' in r.stderr,(r.returncode,r.stderr[:80])
        assert not r.stdout,'invalid frame leaked stdout'
    cases={
      'truncated_magic':b'GMRUN',
      'wrong_magic':b'INVALID!'+u32(1)+u32(3)+u32(3)+b'sm3',
      'zero_arguments':b'GMRUN001'+u32(0)+u32(0),
      'excess_arguments':b'GMRUN001'+u32(257)+u32(0),
      'excess_total':b'GMRUN001'+u32(1)+u32(1048577),
      'excess_item_length':b'GMRUN001'+u32(1)+u32(65537)+u32(65537),
      'truncated_item':b'GMRUN001'+u32(1)+u32(3)+u32(3)+b'sm',
      'embedded_NUL':frame([b'sm3\0']),
      'empty_command':frame(['']),
      'length_underflow_attempt':b'GMRUN001'+u32(2)+u32(2)+u32(3)+b'abc',
      'total_mismatch':b'GMRUN001'+u32(1)+u32(4)+u32(3)+b'sm3',
    }
    for name,data in cases.items(): check('frame_'+name,lambda d=data:invalid(d))
    check('reject_OS_argv',lambda:invalid(frame(['sm3']),('sm3',)))
    def kat():
        r=invoke(frame(['sm3'],b'abc'))
        assert r.returncode==0,'SM3 execution failed'
        assert b'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0' in r.stdout.lower(),'KAT mismatch'
    check('real_SM3_abc_KAT',kat)
    def argv():
        secret='RunnerSecret-'+uuid.uuid4().hex
        proc=subprocess.Popen([runner],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            proc.stdin.write(frame(['sm3_pbkdf2','-pass',secret,'-salt','00112233445566778899aabbccddeeff','-iter','16777215','-outlen','32']))
            proc.stdin.flush(); proc.stdin.close(); time.sleep(.1)
            assert proc.poll() is None,'slow process ended before observation'
            actual=subprocess.check_output(['ps','-p',str(proc.pid),'-o','command='],text=True)
            assert secret not in actual and '-pass' not in actual,'algorithm parameters exposed in argv'
        finally:
            if proc.poll() is None: proc.terminate()
            proc.wait(timeout=5)
            proc.stdout.close(); proc.stderr.close()
    check('stdin_secret_not_in_OS_argv',argv)
    out=pathlib.Path(a.output)/('native_'+uuid.uuid4().hex[:10]);out.mkdir(parents=True)
    counts={s:sum(r['status']==s for r in rows) for s in ('PASS','FAIL')}
    (out/'report.json').write_text(json.dumps({'runner':runner,'counts':counts,'results':rows},indent=2)+'\n')
    print('REPORT',out,'COUNTS',counts)
    return bool(counts['FAIL'])
if __name__=='__main__':raise SystemExit(main())
