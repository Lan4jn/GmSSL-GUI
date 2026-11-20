#!/usr/bin/env python3
import argparse
import hashlib
import pathlib
import struct
import subprocess
import time
import unittest

MAGIC = b'GMRUN001'
RUNNER = None


def frame(args, data=b''):
    args = [a.encode() if isinstance(a,str) else a for a in args]
    return MAGIC + struct.pack('>II',len(args),sum(map(len,args))) + b''.join(struct.pack('>I',len(a))+a for a in args) + data


class RunnerTest(unittest.TestCase):
    def run_frame(self, data):
        return subprocess.run([str(RUNNER)], input=data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=5)
    def test_sm3_abc(self):
        r = self.run_frame(frame(['sm3','-bin'],b'abc'))
        self.assertEqual(r.returncode,0,r.stderr)
        self.assertEqual(r.stdout.hex(),'66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')
    def test_binary_stdin_and_eof(self):
        data = bytes(range(256))*127 + b'\x00tail\xff'
        r = self.run_frame(frame(['sm3','-bin'],data))
        self.assertEqual(r.returncode,0,r.stderr)
        import tempfile
        with tempfile.NamedTemporaryFile() as f:
            f.write(data); f.flush()
            reference = self.run_frame(frame(['sm3','-bin','-in',f.name]))
            self.assertEqual(reference.returncode,0,reference.stderr)
            self.assertEqual(r.stdout,reference.stdout)
        for _ in range(2):
            r = self.run_frame(frame(['sm3','-bin']))
            self.assertEqual(r.stdout.hex(),'1ab21d8355cfa17f8e61194831e81a8f22bec8c728fefb747ed035eb5082aa2b')
    def test_bad_frames(self):
        samples = [b'',MAGIC, b'BADMAGIC'+struct.pack('>II',1,3),
                   MAGIC+struct.pack('>II',0,0), MAGIC+struct.pack('>II',257,0),
                   MAGIC+struct.pack('>II',1,1048577), MAGIC+struct.pack('>III',1,3,0xffffffff),
                   MAGIC+struct.pack('>III',1,3,3)+b'ab', frame([b'sm\x003']),
                   MAGIC+struct.pack('>III',1,4,3)+b'sm3']
        for data in samples:
            r = self.run_frame(data)
            self.assertEqual(r.returncode,64,(data[:24],r.stderr))
            self.assertEqual(r.stdout,b'')
    def test_secret_absent_from_process_argv(self):
        # Block after args are parsed: sm3 waits for the still-open payload pipe.
        secret='secret-argv-marker-244384'
        p = subprocess.Popen([str(RUNNER)],stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        try:
            p.stdin.write(frame(['sm3_hmac','-key',secret.encode().hex(),'-bin']))
            p.stdin.flush()
            time.sleep(.15)
            args=subprocess.check_output(['ps','-p',str(p.pid),'-o','command=']).decode()
            self.assertNotIn(secret,args)
            self.assertNotIn(secret.encode().hex(),args)
            self.assertIn('gmssl-runner',args)
            p.stdin.close()
            self.assertEqual(p.wait(timeout=5),0)
        finally:
            if p.poll() is None: p.kill(); p.wait()
            for stream in (p.stdin,p.stdout,p.stderr):
                if stream and not stream.closed: stream.close()

if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('--runner',type=pathlib.Path,default=pathlib.Path(__file__).parent/'.build/bin/gmssl-runner')
    args, remaining=parser.parse_known_args()
    RUNNER=args.runner.resolve()
    unittest.main(argv=[__file__]+remaining)
