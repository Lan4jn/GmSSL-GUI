#!/usr/bin/env python3
"""Real framed GmSSL runner SAN interop; OpenSSL is an independent verifier."""
import base64
import hashlib
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
import tempfile

RUNNER = Path(sys.argv[1] if len(sys.argv) > 1 else 'native/.build/bin/gmssl-runner').resolve()
OPENSSL = os.environ.get('OPENSSL', 'openssl')


def run(args, ok=True):
    encoded = [str(a).encode() for a in args]
    frame = b'GMRUN001' + struct.pack('>II', len(encoded), sum(map(len, encoded)))
    frame += b''.join(struct.pack('>I', len(a)) + a for a in encoded)
    result = subprocess.run([str(RUNNER)], input=frame, capture_output=True, timeout=30)
    assert (result.returncode == 0) == ok, (args[0], result.returncode, result.stderr.decode(errors='replace'))
    return result


def openssl(*args):
    result = subprocess.run([OPENSSL, *map(str, args)], capture_output=True, timeout=30)
    assert result.returncode == 0, result.stderr.decode(errors='replace')
    return (result.stdout + result.stderr).decode()


def der_wrap(tag, content):
    length = len(content)
    encoded = bytes([length]) if length < 128 else bytes([0x80 + (length.bit_length()+7)//8]) + length.to_bytes((length.bit_length()+7)//8, 'big')
    return bytes([tag]) + encoded + content


def der_children(content):
    result = []
    while content:
        tag, length = content[0], content[1]
        header = 2
        if length & 0x80:
            width = length & 0x7f
            assert 1 <= width <= 4
            length = int.from_bytes(content[2:2+width], 'big')
            header += width
        assert header + length <= len(content)
        result.append((tag, content[header:header+length]))
        content = content[header+length:]
    return result


def malformed_csr_fixture(base, key, output, attrs):
    der = base64.b64decode(''.join(base.read_text().splitlines()[1:-1]))
    outer = der_children(der_children(der)[0][1])
    tbs_fields = der_children(outer[0][1])
    tbs = der_wrap(0x30, b''.join(der_wrap(tag, data) for tag, data in tbs_fields[:-1]) + der_wrap(0xa0, attrs))
    tbs_path, sig_path = output.with_suffix('.der'), output.with_suffix('.sig')
    tbs_path.write_bytes(tbs)
    openssl('pkeyutl', '-sign', '-rawin', '-digest', 'sm3', '-pkeyopt', 'distid:1234567812345678',
        '-inkey', key, '-in', tbs_path, '-out', sig_path)
    signed = der_wrap(0x30, tbs + der_wrap(*outer[1]) + der_wrap(3, bytes([0]) + sig_path.read_bytes()))
    encoded = base64.b64encode(signed).decode()
    output.write_text('-----BEGIN CERTIFICATE REQUEST-----\n' + '\n'.join(encoded[i:i+64] for i in range(0,len(encoded),64)) + '\n-----END CERTIFICATE REQUEST-----\n')


def main():
    with tempfile.TemporaryDirectory(prefix='gmssl-san-') as directory:
        d = Path(directory)
        key, ca, csr, cert = [d / name for name in ('key.pem', 'ca.pem', 'req.pem', 'cert.pem')]
        run(['sm2keygen', '-pass', 'test-only-san-password', '-out', key])
        keyargs = ['-key', key, '-pass', 'test-only-san-password']
        san = ['-subject_dns_name', 'test.example.com', '-subject_ip', '192.168.1.50', '-subject_ip', '2001:db8::50']
        run(['certgen', '-CN', 'SAN CA', '-days', '30', '-ca', '-key_usage', 'keyCertSign', *keyargs, *san, '-out', ca])
        text = openssl('x509', '-in', ca, '-noout', '-text')
        for value in ('DNS:test.example.com', 'IP Address:192.168.1.50', 'IP Address:2001:DB8:0:0:0:0:0:50'):
            assert value in text, value
        print('PASS certgen DNS + IPv4 + IPv6 DER')
        run(['reqgen', '-CN', 'SAN leaf', *keyargs, *san, '-out', csr])
        text = openssl('req', '-in', csr, '-noout', '-text', '-verify', '-vfyopt', 'distid:1234567812345678')
        assert 'verify ok' in text.lower(), text
        assert 'Requested Extensions' in text and 'IP Address:192.168.1.50' in text
        print('PASS reqgen PKCS9 extensionRequest and independent SM2 self-signature')
        signargs = ['reqsign', '-in', csr, '-cacert', ca, '-days', '5', *keyargs]
        run([*signargs, '-out', cert])
        text = openssl('x509', '-in', cert, '-noout', '-text')
        assert 'IP Address:192.168.1.50' in text and 'DNS:test.example.com' in text
        assert 'CA:TRUE' not in text
        openssl('verify', '-CAfile', ca, '-vfyopt', 'distid:1234567812345678', cert)
        print('PASS reqsign inherits SAN only and OpenSSL verifies issuer signature')
        run([*signargs, '-subject_ip', '127.0.0.2', '-out', cert])
        text = openssl('x509', '-in', cert, '-noout', '-ext', 'subjectAltName')
        assert '127.0.0.2' in text and 'test.example.com' not in text
        print('PASS explicit SAN overrides CSR SAN')
        for command in ('certgen', 'reqgen'):
            commandargs = [command, '-CN', 'bad', *keyargs] + (['-days', '5'] if command == 'certgen' else [])
            for invalid in ('192.168.1.999', 'test.example.com', 'fe80::1%en0', '10.0.0.1/24'):
                result = run([*commandargs, '-subject_ip', invalid, '-out', d/'bad.pem'], ok=False)
                assert b'invalid IP literal' in result.stderr
            result = run([*commandargs, *(['-subject_ip', '127.0.0.1'] * 65), '-out', d/'bad.pem'], ok=False)
            assert b'SAN limit exceeded' in result.stderr
            run([*commandargs, '-subject_dns_name', 'a'*254, '-out', d/'bad.pem'], ok=False)
            run([*commandargs, *(['-subject_dns_name', 'a'*253] * 9), '-out', d/'bad.pem'], ok=False)
        for invalid in ('no-address', '::gg'):
            result = run([*signargs, '-subject_ip', invalid, '-out', cert], ok=False)
            assert b'invalid IP literal' in result.stderr
        print('PASS malformed IP and SAN count/length/DER bounds on all three tools')
        dangerous = d/'ca-request.pem'
        fixture_key = d/'fixture-key.pem'
        openssl('genpkey', '-algorithm', 'SM2', '-out', fixture_key)
        openssl('req', '-new', '-key', fixture_key,
            '-subj', '/CN=untrusted-request', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign',
            '-addext', 'subjectAltName=DNS:untrusted.example,IP:192.168.1.51',
            '-sigopt', 'distid:1234567812345678', '-out', dangerous)
        run(['reqsign', '-in', dangerous, '-cacert', ca, '-days', '5', *keyargs, '-out', cert])
        text = openssl('x509', '-in', cert, '-noout', '-text')
        assert 'DNS:untrusted.example' in text and 'IP Address:192.168.1.51' in text
        assert 'CA:TRUE' not in text and 'Certificate Sign' not in text and 'CRL Sign' not in text
        print('PASS requested CA:true/keyCertSign are not inherited')
        unsupported = d/'uri-request.pem'
        openssl('req', '-new', '-key', fixture_key, '-subj', '/CN=uri-request',
            '-addext', 'subjectAltName=URI:https://example.test',
            '-sigopt', 'distid:1234567812345678', '-out', unsupported)
        result = run(['reqsign', '-in', unsupported, '-cacert', ca, '-days', '5', *keyargs, '-out', cert], ok=False)
        assert b'invalid CSR SAN extension request' in result.stderr
        print('PASS SAN outside the reviewed DNS/IP allowlist fails explicitly')
        request_der = base64.b64decode(''.join(dangerous.read_text().splitlines()[1:-1]))
        attrs = der_children(der_children(der_children(request_der)[0][1])[0][1])[-1][1]
        oid_request = bytes.fromhex('06092a864886f70d01090e')
        oid_san = bytes.fromhex('0603551d11')
        def san_attribute(names, copies=1):
            extension = der_wrap(0x30, oid_san + der_wrap(4, der_wrap(0x30, names)))
            return der_wrap(0x30, oid_request + der_wrap(0x31, der_wrap(0x30, extension * copies)))
        for label, invalid_attrs in (
            ('duplicate-request', attrs + attrs),
            ('duplicate-san', san_attribute(der_wrap(0x87, bytes([127, 0, 0, 1])), copies=2)),
            ('invalid-ip-length', san_attribute(der_wrap(0x87, bytes([127, 0, 1])))),
            ('too-many-csr-sans', san_attribute(der_wrap(0x87, bytes([127, 0, 0, 1])) * 65))):
            malformed = d/(label + '.pem')
            malformed_csr_fixture(dangerous, fixture_key, malformed, invalid_attrs)
            result = run(['reqsign', '-in', malformed, '-cacert', ca, '-days', '5', *keyargs, '-out', cert], ok=False)
            assert b'invalid CSR SAN extension request' in result.stderr
        print('PASS signed duplicate extensionRequest/SAN, malformed IP bytes and excessive CSR SAN fail')
        many = d/'many.pem'
        names = ['-subject_ip', '127.0.0.1'] * 64
        run(['reqgen', '-CN', 'many', *keyargs, *names, '-out', many])
        run(['reqsign', '-in', many, '-cacert', ca, '-days', '5', *keyargs, '-out', cert])
        assert openssl('x509', '-in', cert, '-noout', '-ext', 'subjectAltName').count('127.0.0.1') == 64
        print('PASS 64-entry CSR exceeds old 512-byte buffer and signs intact')
        der = bytearray(base64.b64decode(''.join(csr.read_text().splitlines()[1:-1])))
        offset = der.index(b'test.example.com')
        der[offset] ^= 1
        bad = d/'tampered.pem'
        data = base64.b64encode(der).decode()
        bad.write_text('-----BEGIN CERTIFICATE REQUEST-----\n' + '\n'.join(data[i:i+64] for i in range(0,len(data),64)) + '\n-----END CERTIFICATE REQUEST-----\n')
        run(['reqsign', '-in', bad, '-cacert', ca, '-days', '5', *keyargs, '-out', cert], ok=False)
        print('PASS tampered CSR SAN signature fails before issuance')
    root = Path(__file__).resolve().parent
    upstream = Path(os.environ.get('GMSSL_SOURCE_DIR', '/tmp/gmssl-review.V5gpYG/upstream'))
    with tempfile.TemporaryDirectory(prefix='gmssl-overlay-replay-') as directory:
        paths = [Path(directory)/n for n in ('one', 'two')]
        for output in paths:
            result = subprocess.run([sys.executable, str(root/'apply-overlays.py'), str(upstream), str(output)], capture_output=True, timeout=30)
            assert result.returncode == 0, result.stderr.decode()
        assert (paths[0]/'overlays-manifest.json').read_bytes() == (paths[1]/'overlays-manifest.json').read_bytes()
        assert (paths[0]/'overlays.diff').read_bytes() == (paths[1]/'overlays.diff').read_bytes()
        manifest = json.loads((paths[0]/'overlays-manifest.json').read_text())
        for patch in manifest['patches']:
            assert hashlib.sha256((upstream/patch['source_rel']).read_bytes()).hexdigest() == patch['original_sha256']
            assert hashlib.sha256((paths[0]/patch['derived_file']).read_bytes()).hexdigest() == patch['derived_sha256']
    print('PASS overlay digest/manifest/diff reproducibility and unchanged upstream digests')
    print('ALL CERTIFICATE SAN TESTS PASSED')


if __name__ == '__main__':
    main()
