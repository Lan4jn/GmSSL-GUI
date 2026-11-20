#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Real extension KAT/roundtrip/negative suite. No input or secret logging.
Run: python3 native/extension-tests.py --binary native/.extension-test-build/extensions
Use --runner for the production length-prefixed stdin protocol.
"""
import argparse, hashlib, hmac, json, os, pathlib, struct, subprocess, tempfile

P=argparse.ArgumentParser();P.add_argument('--binary',required=True);P.add_argument('--runner',action='store_true');a=P.parse_args()
binary=str(pathlib.Path(a.binary).resolve()); passed=0

def run(cmd,args=(),data=b'',good=True,cwd=None):
    global passed
    argv=[cmd]+[str(x) for x in args]
    if a.runner:
        # Match runner.c protocol, checked by --runner integration test.
        payload=b'GMRUN001'+struct.pack('>II',len(argv),sum(len(x.encode()) for x in argv))
        for arg in argv:
            b=arg.encode();payload+=struct.pack('>I',len(b))+b
        p=subprocess.run([binary],input=payload+data,capture_output=True,cwd=cwd,timeout=40)
    else:p=subprocess.run([binary,*argv],input=data,capture_output=True,cwd=cwd,timeout=40)
    assert (p.returncode==0)==good, (cmd,'unexpected status',p.returncode,p.stderr[-350:])
    if not good:assert not p.stdout,(cmd,'failure published output')
    passed+=1
    return p.stdout

def check(actual,expected,label):
    assert actual==expected,(label,'known answer mismatch')

def sm3_pure(msg: bytes) -> bytes:
    IV = [0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600, 0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e]
    T = [0x79cc4519 if j < 16 else 0x7a879d8a for j in range(64)]
    rotl = lambda x, n: ((x << (n % 32)) & 0xffffffff) | ((x & 0xffffffff) >> ((32 - (n % 32)) % 32))
    FF = lambda x, y, z, j: (x ^ y ^ z) if j < 16 else ((x & y) | (x & z) | (y & z))
    GG = lambda x, y, z, j: (x ^ y ^ z) if j < 16 else ((x & y) | (~x & z))
    P0 = lambda x: x ^ rotl(x, 9) ^ rotl(x, 17)
    P1 = lambda x: x ^ rotl(x, 15) ^ rotl(x, 23)
    l = len(msg) * 8
    msg += b'\x80'
    msg += b'\x00' * ((56 - len(msg) % 64) % 64)
    msg += l.to_bytes(8, 'big')
    V = list(IV)
    for i in range(0, len(msg), 64):
        block = msg[i:i+64]
        W = [int.from_bytes(block[j:j+4], 'big') for j in range(0, 64, 4)]
        for j in range(16, 68):
            W.append(P1(W[j-16] ^ W[j-9] ^ rotl(W[j-3], 15)) ^ rotl(W[j-13], 7) ^ W[j-6])
        W1 = [W[j] ^ W[j+4] for j in range(64)]
        A, B, C, D, E, F, G, H = V
        for j in range(64):
            SS1 = rotl((rotl(A, 12) + E + rotl(T[j], j)) & 0xffffffff, 7)
            SS2 = SS1 ^ rotl(A, 12)
            TT1 = (FF(A, B, C, j) + D + SS2 + W1[j]) & 0xffffffff
            TT2 = (GG(E, F, G, j) + H + SS1 + W[j]) & 0xffffffff
            D, C, B, A = C, rotl(B, 9), A, TT1
            H, G, F, E = G, rotl(F, 19), E, P0(TT2)
        V = [x ^ y for x, y in zip(V, (A, B, C, D, E, F, G, H))]
    return b''.join(x.to_bytes(4, 'big') for x in V)

has_sm3 = 'sm3' in hashlib.algorithms_available
def hv(name,data):
    if name=='sm3' and not has_sm3: return sm3_pure(data)
    return hashlib.new(name.replace('-','_'),data).digest()

def hmac_digest(key,msg,alg):
    if alg=='sm3' and not has_sm3:
        if len(key)>64: key=sm3_pure(key)
        key=key.ljust(64,b'\x00')
        return sm3_pure(bytes(x^0x5c for x in key)+sm3_pure(bytes(x^0x36 for x in key)+msg))
    return hmac.new(key,msg,alg.replace('-','_')).digest()

def pbkdf2_digest(alg,passw,salt,iters,dklen):
    if alg=='sm3' and not has_sm3:
        dk=b'';b_num=1
        while len(dk)<dklen:
            u=hmac_digest(passw,salt+struct.pack('>I',b_num),'sm3')
            t=u
            for _ in range(iters-1):
                u=hmac_digest(passw,u,'sm3')
                t=bytes(x^y for x,y in zip(t,u))
            dk+=t;b_num+=1
        return dk[:dklen]
    return hashlib.pbkdf2_hmac(alg.replace('-','_'),passw,salt,iters,dklen)

mds=['sm3','sha1','sha224','sha256','sha384','sha512','sha512-224','sha512-256']
for alg in mds+['sha3-256','sha3-512']:
    check(run('api_digest',['-alg',alg,'-bin'],b'abc'),hv(alg,b'abc'),alg)
for alg in ['shake128','shake256']:
    expected=getattr(hashlib,alg.replace('shake','shake_'))(b'abc').digest(137)
    check(run('api_digest',['-alg',alg,'-outlen',137,'-bin'],b'abc'),expected,alg)
    run('api_digest',['-alg',alg],good=False)
for alg in mds:
    check(run('api_hmac',['-alg',alg,'-key','0b'*20,'-bin'],b'Hi There'),hmac_digest(b'\x0b'*20,b'Hi There',alg),alg+' hmac')
    check(run('api_pbkdf2',['-alg',alg,'-pass','password','-salt','73616c74','-iter',2,'-outlen',37,'-bin']),pbkdf2_digest(alg,b'password',b'salt',2,37),alg+' pbkdf2')
    salt=b'salt';ikm=b'input key material';info=b'context';L=42
    prk=hmac_digest(salt,ikm,alg);block=b'';okm=b''
    for i in range(1,4):block=hmac_digest(prk,block+info+bytes([i]),alg);okm+=block
    check(run('api_hkdf',['-alg',alg,'-salt',salt.hex(),'-info',info.hex(),'-outlen',L,'-bin'],ikm),okm[:L],alg+' hkdf')
# RFC5869 case 1
check(run('api_hkdf',['-alg','sha256','-salt','000102030405060708090a0b0c','-info','f0f1f2f3f4f5f6f7f8f9','-outlen',42,'-bin'],b'\x0b'*22),bytes.fromhex('3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865'),'RFC5869')
kdf=b''.join(hv('sm3',b'abc'+struct.pack('>I',i)) for i in range(1,4))[:70]
check(run('api_sm3_kdf',['-outlen',70,'-bin'],b'abc'),kdf,'SM3 counter KDF')
# NIST SP800-38A ECB first block across key sizes.
plain=bytes.fromhex('00112233445566778899aabbccddeeff')
for key,cipher in [('000102030405060708090a0b0c0d0e0f','69c4e0d86a7b0430d8cdb78070b4c55a'),('000102030405060708090a0b0c0d0e0f1011121314151617','dda97ca4864cdfe06eaf70a0ec0d7191'),('000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f','8ea2b7ca516745bfeafc49904b496089')]:
    check(run('api_aes',['-mode','ecb','-op','encrypt','-key',key],plain),bytes.fromhex(cipher),'AES ECB')
    check(run('api_aes',['-mode','ecb','-op','decrypt','-key',key],bytes.fromhex(cipher)),plain,'AES ECB decrypt')
# NIST GCM empty/zero block authenticated vectors.
for data,cipher in [(b'','58e2fccefa7e3061367f1d57a4e7455a'),(b'\0'*16,'0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf')]:
    check(run('api_aes',['-mode','gcm','-op','encrypt','-key','00'*16,'-iv','00'*12],data),bytes.fromhex(cipher),'NIST GCM')
# RFC3610 packet 1 (8-byte AAD, 23-byte payload, 8-byte tag).
ccm_args=['-mode','ccm','-key','c0c1c2c3c4c5c6c7c8c9cacbcccdcecf','-iv','00000003020100a0a1a2a3a4a5','-aad','0001020304050607','-taglen',8]
check(run('api_aes',ccm_args+['-op','encrypt'],bytes(range(8,31))),bytes.fromhex('588c979a61c663d2f066d0c2c0f989806d5f6b61dac38417e8d12cfdf926e0'),'RFC3610')
# NIST CBC and CTR first block.
key='2b7e151628aed2a6abf7158809cf4f3c';pt=bytes.fromhex('6bc1bee22e409f96e93d7e117393172a')
for mode,iv,expected in [('cbc','000102030405060708090a0b0c0d0e0f','7649abac8119b246cee98e9b12e9197d'),('ctr','f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff','874d6191b620e3261bef6864990db6ce')]:
    check(run('api_aes',['-mode',mode,'-op','encrypt','-key',key,'-iv',iv],pt),bytes.fromhex(expected),'NIST '+mode)
for size in (16,24,32):
    for mode in ('cbc','ctr','gcm','ccm'):
        base=['-mode',mode,'-key','11'*size,'-iv','22'*(12 if mode in ('gcm','ccm') else 16)]
        if mode=='cbc':base+=['-padding','pkcs7']
        if mode in ('gcm','ccm'):base+=['-aad','00ff']
        for msg in (b'',b'\x00binary\xfftext\x00',b'X'*32):
            cipher=run('api_aes',base+['-op','encrypt'],msg)
            check(run('api_aes',base+['-op','decrypt'],cipher),msg,'AES '+mode+' roundtrip')
            if mode in ('gcm','ccm'):
                bad=cipher[:-1]+bytes([cipher[-1]^1]);run('api_aes',base+['-op','decrypt'],bad,good=False)
# P256/P384 and SM2 d=1 public generator plus d=2 ECDH symmetry.
generators={'P256':'046b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c2964fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5','P384':'04aa87ca22be8b05378eb1c71ef320ad746e1d3b628ba79b9859f741e082542a385502f25dbf55296c3a545e3872760ab73617de4a96262c6f5d9e98bf9292dc29f8f41dbd289a147ce9da3113b5f0b8c00a60b1ce1d7e819d7a431d7c90ea0e5f','sm2':'0432c4ae2c1f1981195f9904466a39c9948fe30bbff2660be1715a4589334c74c7bc3736a2f4f6779c59bdcee36b692153d0a9877cc62a474002df32e52139f0a0'}
for curve in ('P256','P384','sm2'):
    size=48 if curve=='P384' else 32;k1='00'*(size-1)+'01';k2='00'*(size-1)+'02'
    pub1=run('api_ec_public',['-curve',curve,'-key',k1,'-bin']);pub2=run('api_ec_public',['-curve',curve,'-key',k2,'-bin'])
    check(pub1,bytes.fromhex(generators[curve]),curve+' generator KAT')
    cmd='api_sm2_ecdh' if curve=='sm2' else 'api_ecdh';base=[] if curve=='sm2' else ['-curve',curve]
    x=run(cmd,base+['-key',k1,'-pub',pub2.hex(),'-bin']);y=run(cmd,base+['-key',k2,'-pub',pub1.hex(),'-bin'])
    check(x,y,curve+' ECDH symmetry');check(x,pub2[1:1+size],curve+' ECDH d=1 KAT')
    run(cmd,base+['-key',k1,'-pub','04'+'00'*(2*size)],good=False)
    run('api_ec_public',['-curve',curve,'-key','00'*size],good=False)
    run('api_ec_public',['-curve',curve,'-key','ff'*size],good=False)
    if curve!='sm2':
        for alg in ('sha256','sha384'):
            signature=run('api_ec_sign',['-curve',curve,'-alg',alg,'-key',k1,'-bin'],b'message')
            args=['-curve',curve,'-alg',alg,'-pub',pub1.hex(),'-sig',signature.hex()]
            run('api_ec_verify',args,b'message');run('api_ec_verify',args,b'changed',good=False)
            run('api_ec_verify',args[:-1]+[signature.hex()+'00'],b'message',good=False)

# ZUC-128 MAC (EIA3 test vector 0 + 50-byte zero vector)
check(run('api_zuc_mac',['-key','00'*16,'-iv','00'*16,'-nbits',1,'-bin'],b'\x00'),bytes.fromhex('c8a9595e'),'ZUC-128 EIA-3 1-bit KAT')
check(run('api_zuc_mac',['-key','00'*16,'-iv','00'*16],b'\x00'*50).decode().strip(),'508dd5ff','ZUC-128 MAC 50-byte KAT')
# ZUC-128 MAC bit validity checks: unused trailing bits must be zero
run('api_zuc_mac',['-key','00'*16,'-iv','00'*16,'-nbits',1],b'\x01',good=False)
run('api_zuc_mac',['-key','00'*16,'-iv','00'*16,'-nbits',9],b'\x00',good=False)
run('api_zuc_mac',['-key','00'*15,'-iv','00'*16],b'\x00',good=False)

# ZUC-256 MAC KATs across 32, 64, 128 bit tags
check(run('api_zuc256_mac',['-key','00'*32,'-iv','00'*23,'-macbits',32],b'\x00'*50).decode().strip(),'9b972a74','ZUC-256 MAC32 KAT')
check(run('api_zuc256_mac',['-key','00'*32,'-iv','00'*23,'-macbits',64],b'\x00'*50).decode().strip(),'673e54990034d38c','ZUC-256 MAC64 KAT')
check(run('api_zuc256_mac',['-key','00'*32,'-iv','00'*23,'-macbits',128],b'\x00'*50).decode().strip(),'d85e54bbcb9600967084c952a1654b26','ZUC-256 MAC128 KAT')
# ZUC-256 negative checks
run('api_zuc256_mac',['-key','00'*32,'-iv','00'*23,'-macbits',48],b'\x00'*50,good=False)
run('api_zuc256_mac',['-key','00'*31,'-iv','00'*23],b'\x00',good=False)
run('api_zuc256_mac',['-key','00'*32,'-iv','00'*22],b'\x00',good=False)

# All command negative cases, without secret echo.
for cmd,args in [
    ('api_digest',['-alg','bad']),('api_digest',['-alg','sha256','-outlen',5]),
    ('api_hmac',['-alg','sha256','-key','x']),('api_hkdf',['-alg','sha1','-outlen',4097,'-salt','00']),
    ('api_pbkdf2',['-alg','sha256','-pass','x','-salt','00','-iter',1000000,'-outlen',4096]),
    ('api_sm3_kdf',['-outlen',0]),('api_aes',['-mode','gcm','-op','decrypt','-key','00'*16,'-iv','00'*12]),
    ('api_ec_sign',['-curve','P256','-key','01','-alg','sha256']),('api_ec_verify',['-curve','P384','-pub','00','-sig','00','-alg','sha384']),
    ('api_ecdh',['-curve','bad','-key','01','-pub','00']),('api_sm2_ecdh',['-key','01','-pub','00']),
    ('api_ec_public',['-curve','bad','-key','01']),
    ('api_zuc_mac',['-key','00'*16]),('api_zuc256_mac',['-key','00'*32]),
    ('api_sm9_kem',['-op','invalid']),('api_sm9_kem',['-op','encrypt','-id','Alice','-outlen',0])
]:run(cmd,args,good=False)
for args in (['-alg','sha256','-alg','sha1'],['-alg','sha256','-bogus','1'],['-alg']):run('api_digest',args,good=False)
for extra in (['-taglen',0],['-taglen',5],['-iv',''],['-padding','pkcs7']):run('api_aes',['-mode','gcm','-op','encrypt','-key','00'*16,'-iv','00'*12]+extra,good=False)
run('api_aes',['-mode','ctr','-op','encrypt','-key','00'*16,'-iv','ff'*16],b'x'*17,good=False)
run('api_aes',['-mode','ccm','-op','encrypt','-key','00'*16,'-iv','00'*13],b'x'*65536,good=False)
run('api_digest',['-alg','sha256'],b'X'*(16*1024*1024+1),good=False)

with tempfile.TemporaryDirectory() as tmp:
    root=pathlib.Path(tmp);(root/'input').mkdir();(root/'output').mkdir();inp=root/'input'/'data.bin';out=root/'output'/'hash.bin';inp.write_bytes(b'abc')
    run('api_digest',['-alg','sha256','-in',inp,'-out',out,'-bin'],cwd=tmp)
    check(out.read_bytes(),hashlib.sha256(b'abc').digest(),'isolated files')
    run('api_digest',['-alg','sha256','-in',inp,'-out',out],good=False,cwd=tmp)
    (root/'input'/'link').symlink_to(inp)
    run('api_digest',['-alg','sha256','-in',root/'input'/'link'],good=False,cwd=tmp)
    run('api_digest',['-alg','sha256','-in',root/'input'/'../input/data.bin','-out',root/'output'/'next.bin'],cwd=tmp)
    run('api_digest',['-alg','sha256','-in','/etc/hosts'],good=False,cwd=tmp)
    run('api_digest',['-alg','sha256','-out',root/'outside.bin'],good=False,cwd=tmp)
    failed=root/'output'/'unauthenticated.bin'
    run('api_aes',['-mode','gcm','-op','decrypt','-key','00'*16,'-iv','00'*12,'-out',failed],b'\0'*16,good=False,cwd=tmp)
    assert not failed.exists(),'authentication failure created output file'
    failed=root/'output'/'ccm-unauthenticated.bin'
    run('api_aes',['-mode','ccm','-op','decrypt','-key','00'*16,'-iv','00'*12,'-out',failed],b'\0'*16,good=False,cwd=tmp)
    assert not failed.exists(),'CCM authentication failure created output file'
    (root/'output'/'symlink.bin').symlink_to(root/'outside.bin')
    run('api_digest',['-alg','sha256','-out',root/'output'/'symlink.bin'],good=False,cwd=tmp)

    # SM9 KEM setup and roundtrip tests
    gmssl_bin='/tmp/gmssl-review.V5gpYG/build/bin/gmssl'
    subprocess.run([gmssl_bin,'sm9setup','-alg','sm9encrypt','-pass','P@ssw0rd','-out',str(root/'input'/'msk.pem'),'-pubout',str(root/'input'/'mpk.pem')],check=True)
    subprocess.run([gmssl_bin,'sm9keygen','-alg','sm9encrypt','-in',str(root/'input'/'msk.pem'),'-inpass','P@ssw0rd','-id','Alice','-out',str(root/'input'/'key.pem'),'-outpass','123456'],check=True)

    # Encrypt
    c_out = root/'output'/'C.bin'
    k_out = root/'output'/'K.bin'
    run('api_sm9_kem',['-op','encrypt','-pubmaster',root/'input'/'mpk.pem','-id','Alice','-outlen',32,'-cipherout',c_out,'-out',k_out,'-bin'],cwd=tmp)
    k1 = k_out.read_bytes()
    c1 = c_out.read_bytes()
    check(len(k1),32,'SM9 KEM K length')
    check(len(c1),65,'SM9 KEM C point length')
    check(c1[0],4,'SM9 KEM C uncompressed point header')

    # Decrypt binary C
    (root/'input'/'C.bin').write_bytes(c1)
    k2_out = root/'output'/'K2.bin'
    run('api_sm9_kem',['-op','decrypt','-key',root/'input'/'key.pem','-pass','123456','-id','Alice','-outlen',32,'-in',root/'input'/'C.bin','-out',k2_out,'-bin'],cwd=tmp)
    check(k2_out.read_bytes(),k1,'SM9 KEM decrypt roundtrip')

    # Decrypt via Hex stdin
    hex_k = run('api_sm9_kem',['-op','decrypt','-key',root/'input'/'key.pem','-pass','123456','-id','Alice','-outlen',32],data=c1.hex().encode()+b'\n',cwd=tmp)
    check(bytes.fromhex(hex_k.decode().strip()),k1,'SM9 KEM decrypt hex stdin')

    # Negative SM9 cases:
    # 1. Wrong password
    run('api_sm9_kem',['-op','decrypt','-key',root/'input'/'key.pem','-pass','badpass','-id','Alice','-outlen',32,'-in',root/'input'/'C.bin'],good=False,cwd=tmp)
    # 2. Corrupted ciphertext point (invalid header 0x05)
    (root/'input'/'bad_c.bin').write_bytes(b'\x05'+c1[1:])
    run('api_sm9_kem',['-op','decrypt','-key',root/'input'/'key.pem','-pass','123456','-id','Alice','-outlen',32,'-in',root/'input'/'bad_c.bin'],good=False,cwd=tmp)
    # 3. Wrong ID derives different K (non-authenticated KEM property)
    k_bob = run('api_sm9_kem',['-op','decrypt','-key',root/'input'/'key.pem','-pass','123456','-id','Bob','-outlen',32,'-in',root/'input'/'C.bin','-bin'],cwd=tmp)
    assert k_bob != k1, 'Different ID derived identical K!'
    # 4. Outlen > 4096
    run('api_sm9_kem',['-op','encrypt','-pubmaster',root/'input'/'mpk.pem','-id','Alice','-outlen',4097,'-cipherout',root/'output'/'C2.bin'],good=False,cwd=tmp)

print(json.dumps({'passedInvocations':passed,'status':'PASS','binaryMode':'runner' if a.runner else 'standalone','coverage':'14 commands; KAT, roundtrip, tag/signature tamper, bounds and file handling'},ensure_ascii=False))
