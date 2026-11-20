#!/usr/bin/env python3
"""Source-derived inventory plus reviewed classifications and UX metadata; not a claim of tested coverage."""
import argparse
import hashlib
import runpy
import json
import pathlib
import re

COMMIT = '24ae482701a7b124826c382fffc55c19f76d475d'
STATEFUL = {'lmssign', 'hsssign', 'xmsssign', 'xmssmtsign'}
HARDWARE = {'sdfinfo', 'sdfdigest', 'sdfexport', 'sdfsign', 'sdfencrypt', 'sdfdecrypt', 'sdftest', 'skfutil'}
OUTPUT = {'out', 'pubout', 'outkey', 'keyout', 'exch_keyout', 'secret_state_out', 'certout', 'sess_out', 'export', 'cipherout'}
FILES = {'in', 'key', 'pubkey', 'cert', 'cacert', 'certs', 'sig', 'pubmaster', 'peer_pubkey', 'peer_cert', 'exch_key', 'secret_state', 'reqin', 'respin', 'signer', 'single_exts', 'response_exts', 'sess_in', 'log_key', 'rcptcert', 'crl', 'ocsp', 'precert'}
INTEGER = {'outlen', 'iter', 'taglen', 'sbytes', 'data_unit_size', 'bearer', 'direction', 'keylen', 'days', 'serial_len', 'path_len_constraint', 'inhibit_any_policy', 'crl_num', 'delta_crl_indicator', 'verify_depth', 'port', 'max_key_exchanges', 'key_update_seq_num', 'max_early_data_size', 'at_least', 'clock_skew'}
SECRET = {'pass', 'inpass', 'outpass', 'exch_pass'}
HEX = {'iv', 'salt', 'aad_hex', 'id_hex', 'peer_id_hex', 'req_sm2_id_hex', 'sm2_id_hex', 'h', 'count', 'psk_key', 'ticket_key', 'issuer_key_hash', 'tweak'}
RANGES = {'outlen': (1, 16777216), 'iter': (10000, 16777215), 'taglen': (4, 16), 'sbytes': (1, 16), 'data_unit_size': (16, 16777216), 'bearer': (0,31), 'direction': (0,1), 'keylen': (1,255), 'days': (1,36500), 'serial_len': (1,20), 'port': (1024,65535), 'verify_depth': (0,10), 'max_key_exchanges': (1,16), 'max_early_data_size': (0,16777216)}

# Precise evidence-based enums from GmSSL C source headers & implementations
ENUM_DEFINITIONS = {
    'curve': ['secp256r1', 'secp384r1'],
    'supported_group': ['sm2p256v1', 'prime256v1'],
    'sig_alg': ['sm2sig_sm3', 'ecdsa_secp256r1_sha256'],
    'algor': ['ecPublicKey', 'lms-hashsig', 'hss-lms-hashsig', 'xmss-hashsig', 'xmssmt-hashsig', 'sphincs-hashsig'],
    'cert_sig_alg': ['sm2sign-with-sm3', 'ecdsa-with-sha256', 'ecdsa-with-sha384', 'ecdsa-with-sha512', 'lms-hashsig', 'hss-lms-hashsig', 'xmss-hashsig', 'xmssmt-hashsig', 'sphincs-hashsig'],
    'digest_alg': ['sm3', 'sha1', 'sha224', 'sha256', 'sha384', 'sha512'],
    'tlcp_cipher': ['TLS_ECC_SM4_CBC_SM3', 'TLS_ECC_SM4_GCM_SM3', 'TLS_ECDHE_SM4_CBC_SM3', 'TLS_ECDHE_SM4_GCM_SM3'],
    'tls12_cipher': ['TLS_ECDHE_SM4_CBC_SM3', 'TLS_ECDHE_SM4_GCM_SM3', 'TLS_ECDHE_ECDSA_WITH_AES_128_CBC_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256', 'TLS_ECDHE_ECDSA_WITH_AES_128_CCM'],
    'tls13_cipher': ['TLS_SM4_GCM_SM3', 'TLS_SM4_CCM_SM3', 'TLS_AES_128_GCM_SHA256', 'TLS_AES_128_CCM_SHA256'],
    'quic_cipher': ['TLS_AES_128_GCM_SHA256'],
    'key_usage': ['digitalSignature', 'nonRepudiation', 'keyEncipherment', 'dataEncipherment', 'keyAgreement', 'keyCertSign', 'cRLSign', 'encipherOnly', 'decipherOnly'],
    'ext_key_usage': ['serverAuth', 'clientAuth', 'codeSigning', 'emailProtection', 'timeStamping', 'OCSPSigning', 'anyExtendedKeyUsage'],
    'crl_reason': ['unspecified', 'keyCompromise', 'cACompromise', 'affiliationChanged', 'superseded', 'cessationOfOperation', 'certificateHold', 'removeFromCRL', 'privilegeWithdrawn', 'aACompromise'],
    'lms_type': ['LMS_SM3_M32_H5', 'LMS_SM3_M32_H10', 'LMS_SM3_M32_H15', 'LMS_SM3_M32_H20', 'LMS_SM3_M32_H25'],
    'xmss_type': ['XMSS_SM3_10_256', 'XMSS_SM3_16_256', 'XMSS_SM3_20_256'],
    'xmssmt_type': ['XMSSMT_SM3_20_2_256', 'XMSSMT_SM3_20_4_256', 'XMSSMT_SM3_40_2_256', 'XMSSMT_SM3_40_4_256', 'XMSSMT_SM3_40_8_256', 'XMSSMT_SM3_60_3_256', 'XMSSMT_SM3_60_6_256', 'XMSSMT_SM3_60_12_256']
}

CHINESE_LABELS = {
    'pubkey': '公钥文件', 'cert': '证书文件', 'cacert': '根/CA证书文件',
    'pass': '私钥密码', 'inpass': '输入私钥密码', 'outpass': '输出私钥密码',
    'exch_pass': '临时协商私钥密码', 'curve': '椭圆曲线', 'outlen': '输出字节数',
    'hex': 'HEX十六进制格式', 'bin': '原始二进制格式', 'days': '有效天数',
    'CN': '通用名称 (CN)', 'O': '组织名称 (O)', 'OU': '部门名称 (OU)',
    'C': '国家代码 (C)', 'ST': '省份/州 (ST)', 'L': '城市/地区 (L)',
    'ca': '作为CA证书', 'key_usage': '密钥用法 (KeyUsage)', 'ext_key_usage': '扩展用法 (ExtKeyUsage)',
    'sig_alg': '签名算法', 'algor': '公钥体系', 'cipher_suite': '加密套件',
    'supported_group': '支持曲线组', 'host': '目标主机地址', 'port': '网络端口',
    'server_name': 'SNI服务器名', 'stage': '协商阶段',
    'id': '身份标识 (ID)', 'id_hex': 'HEX身份标识', 'sm2_id': 'SM2用户ID',
    'sm2_id_hex': 'HEX SM2用户ID', 'iv': '初始向量 (IV)', 'salt': '盐值 (Salt)',
    'iter': '迭代次数', 'taglen': '认证标签长度', 'aad': '附加认证数据 (AAD)',
    'aad_hex': 'HEX附加数据', 'tweak': '调整值 (Tweak)', 'serial_len': '序列号长度',
    'path_len_constraint': 'CA路径深度约束', 'crl_http_uri': 'CRL发布HTTP地址',
    'ocsp_uri': 'OCSP查询地址', 'ca_issuers_uri': 'CA证书下载地址', 'reason': '吊销原因',
    'invalid_date': '失效时间', 'rcptcert': '接收者证书', 'lms_type': 'LMS参数类型',
    'xmss_type': 'XMSS参数类型', 'xmssmt_type': 'XMSS^MT参数类型', 'mode': '分组工作模式',
    'op': '操作类型', 'help': '显示帮助信息', 'encrypt': '执行加密操作', 'decrypt': '执行解密操作',
    'rdrand': '硬件RDRAND指令', 'rdseed': '硬件RDSEED指令',
    'gen_authority_key_id': '生成颁发者密钥标识 (AKID)',
    'gen_subject_key_id': '生成使用者密钥标识 (SKID)',
    'subject_ip': '使用者备用IP地址 (SAN)', 'subject_dns_name': '使用者备用DNS域名 (SAN)', 'issuer_dns_name': '颁发者备用DNS域名',
    'crl_ldap_uri': 'CRL发布LDAP地址', 'inhibit_any_policy': '抑制任意策略跳数',
    'tlcp_server': '作为TLCP服务端证书校验', 'server': '作为服务端证书校验',
    'client': '作为客户端证书校验', 'hostname': '校验预期主机名/域名',
    'url': 'OCSP响应查询URL', 'verbose': '详细调试输出',
    'reqin': 'OCSP请求输入文件', 'respin': 'OCSP响应输入文件', 'signer': '签名者证书文件',
    'status': 'OCSP响应状态', 'revocation_time': '吊销生效时间', 'revocation_reason': '吊销原因编码',
    'this_update': '本期更新时间', 'next_update': '下期更新时间', 'produced_at': '响应产生时间',
    'resp_key_id': '响应包含ResponderID密钥哈希', 'single_exts': '单证书扩展输入文件',
    'response_exts': '响应体扩展输入文件', 'certs': '附加证书列表文件', 'time': '指定验签参照时间',
    'clock_skew': '允许时钟漂移秒数', 'crl_num': 'CRL编号序号', 'delta_crl_indicator': '增量CRL指示编号',
    'http_uri': 'CRL分发HTTP地址', 'ldap_uri': 'CRL分发LDAP地址', 'req_sm2_id': '请求者SM2用户ID',
    'req_sm2_id_hex': '请求者HEX SM2用户ID', 'sig': '签名值输入文件', 'peer_cert': '对端证书文件',
    'peer_pubkey': '对端公钥文件', 'peer_id': '对端身份标识 (ID)', 'peer_id_hex': '对端HEX身份标识',
    'exch_keyout': '协商临时公钥输出文件', 'exch_key': '协商临时私钥输入文件',
    'secret_state_out': '协商秘密状态输出文件', 'secret_state': '协商秘密状态输入文件',
    'keylen': '导出对称密钥字节长度', 'keyout': '导出对称密钥输出文件', 'in_str': '直接输入文本内容',
    'pkcs7_padding': '启用PKCS#7标准填充', 'sbytes': 'CFB分段字节数', 'data_unit_size': 'XTS数据单元大小',
    'digits': 'FF1待加密数字串', 'idcard': 'FF1身份证号模式校验', 'bankcard': 'FF1银行卡号模式校验',
    'count': '3GPP计数值 (HEX)', 'bearer': '3GPP承载标识 (0..31)', 'direction': '3GPP传输方向 (0上行/1下行)',
    'h': 'GHASH子密钥H (16字节HEX)', 'alg': '算法模式/算法类型', 'pubmaster': 'KGC主公钥文件',
    'verify_depth': '证书链最大验证深度', 'trusted_ca_keys': '发送受信任CA列表扩展',
    'alpn': 'ALPN应用层协议协商', 'client_cert_optional': '客户端证书可选模式',
    'get': '连接建立后发送HTTP GET请求路径', 'certout': '保存服务端证书到文件',
    'cert_request': '请求客户端提供双向证书', 'www': '简易Web服务器模式',
    'renegotiation_info': '安全重协商扩展', 'renegotiation_info_scsv': '发送重协商SCSV信令',
    'signature_algorithms_cert': '支持证书专用签名算法扩展', 'certificate_authorities': '发送CA主体扩展',
    'status_request': '启用OCSP Stapling状态请求', 'ct': '启用证书透明度 (CT) 扩展',
    'post_handshake_auth': '握手后重认证模式', 'sess_in': 'TLS会话恢复凭据文件',
    'sess_out': '保存TLS会话凭据文件', 'psk_ke': '仅PSK预共享密钥交换',
    'psk_dhe_ke': 'PSK与DHE混合密钥交换', 'psk_identity': 'PSK身份标识字符串',
    'psk_cipher_suite': 'PSK专用加密套件', 'psk_key': 'PSK预共享密钥 (HEX)',
    'ticket_key': '会话票据加密密钥 (HEX)', 'early_data': 'TLS 1.3 0-RTT早期数据',
    'max_early_data_size': '0-RTT最大早期数据大小', 'max_key_exchanges': '最大密钥重协商次数',
    'key_update_seq_num': '触发KeyUpdate的序列号', 'tls13_change_cipher_spec': '发送TLS 1.3中间兼容CCS包',
    'new_session_ticket': '主动下发SessionTicket参数', 'precert': '预证书文件 (Precertificate)',
    'issuer_key_hash': '颁发者公钥哈希 (HEX)', 'log_key': 'CT日志服务公钥文件',
    'at_least': '最少SCT有效证明数', 'pubout': '公钥输出文件', 'export': '导出的原始私钥输出文件',
    'lms_types': 'HSS各层LMS算法组合', 'outkey': '解封装对称密钥输出文件'
}


def category(c):
    if c.startswith(('tls','tlcp','quic')): return 'protocol'
    if c.startswith(('lms','hss','xmss','sphincs','kyber')): return 'pqc'
    if c.startswith(('cert','crl','req','ocsp','sct')): return 'certificate'
    if c.startswith(('sm2','sm9')):
        if c.endswith(('keygen','setup')): return 'key'
        return 'asymmetric'
    if c in ('eckeygen',): return 'key'
    if c in ('rand',): return 'random'
    if c.startswith('sm3_pbkdf2'): return 'kdf'
    if c.startswith('sm3_hmac') or c.endswith(('_mac',)) or c in ('ghash','zuc_128_eia3'): return 'mac'
    if c in ('sm3',): return 'digest'
    if c.startswith(('sm4','zuc')): return 'symmetric'
    if c.startswith('cms'): return 'envelope'
    return 'algorithm'


def enrich_parameter(command, p):
    name = p['name']
    typ = p['type']
    
    # 1. Context-sensitive Chinese Label
    if name == 'key':
        if typ == 'HEX':
            if command in ('sm3_hmac', 'sm4_cbc_mac', 'zuc_128_eia3', 'api_hmac', 'api_zuc_mac', 'api_zuc256_mac'):
                p['label'] = 'MAC密钥 (HEX)'
            elif command in ('api_ec_public', 'api_ec_sign', 'api_ecdh', 'api_sm2_ecdh'):
                p['label'] = '椭圆曲线私钥标量 (HEX)'
            else:
                p['label'] = '对称密钥 (HEX)'
        elif typ == 'INPUT_FILE':
            if command in ('lmssign', 'hsssign', 'xmsssign', 'xmssmtsign'):
                p['label'] = '有状态私钥文件'
            else:
                p['label'] = '私钥文件'
        else:
            p['label'] = '密钥'
    elif name == 'in':
        if command in ('certverify', 'certparse'):
            p['label'] = '证书输入文件'
        elif command in ('crlverify', 'crlparse', 'crlgen'):
            p['label'] = 'CRL输入文件'
        elif command in ('reqparse', 'reqsign'):
            p['label'] = 'CSR证书请求文件'
        elif command in ('sm2sign', 'sm9sign', 'cmssign', 'lmssign', 'hsssign', 'xmsssign', 'xmssmtsign', 'sphincssign', 'api_ec_sign'):
            p['label'] = '待签名原始数据文件'
        elif command in ('sm2verify', 'sm9verify', 'cmsverify', 'lmsverify', 'hssverify', 'xmssverify', 'xmssmtverify', 'sphincsverify', 'api_ec_verify'):
            p['label'] = '待验签原始数据文件'
        elif command in ('sm2encrypt', 'sm9encrypt', 'cmsencrypt') or command.startswith(('sm4_', 'zuc')) or command in ('api_aes',):
            p['label'] = '待加密明文文件'
        elif command in ('sm2decrypt', 'sm9decrypt', 'cmsdecrypt'):
            p['label'] = '待解密密文文件'
        elif command in ('sm3', 'api_digest'):
            p['label'] = '待计算摘要文件'
        elif command in ('sm3_hmac', 'api_hmac', 'sm4_cbc_mac', 'zuc_128_eia3', 'api_zuc_mac', 'api_zuc256_mac'):
            p['label'] = '待计算MAC文件'
        elif command in ('sm9keygen',):
            p['label'] = 'KGC主私钥文件'
        else:
            p['label'] = '输入文件'
    elif name == 'out':
        if command.endswith('keygen') or command.endswith('setup'):
            p['label'] = '私钥输出文件'
        elif command.endswith('sign') or command in ('ocspsign',):
            p['label'] = '签名输出文件'
        elif command.startswith(('sm4_', 'zuc', 'cmsencrypt')) or command in ('api_aes',):
            p['label'] = '密文输出文件'
        elif command in ('sm3', 'api_digest'):
            p['label'] = '摘要输出文件'
        elif command in ('sm3_hmac', 'api_hmac', 'sm4_cbc_mac', 'zuc_128_eia3', 'api_zuc_mac', 'api_zuc256_mac'):
            p['label'] = 'MAC输出文件'
        elif command in ('sm3_pbkdf2', 'api_hkdf', 'api_pbkdf2', 'api_sm3_kdf', 'api_sm9_kem'):
            p['label'] = '派生密钥输出文件'
        elif command in ('certgen', 'reqsign'):
            p['label'] = '证书输出文件'
        elif command in ('crlgen',):
            p['label'] = 'CRL输出文件'
        elif command in ('reqgen',):
            p['label'] = 'CSR请求输出文件'
        elif command == 'rand':
            p['label'] = '随机数输出文件'
        elif command in ('sm2decrypt', 'sm9decrypt', 'cmsdecrypt'):
            p['label'] = '解密明文输出文件'
        else:
            p['label'] = '输出文件'
    elif name in CHINESE_LABELS:
        p['label'] = CHINESE_LABELS[name]
    else:
        p['label'] = name

    # 2. CredentialKeyParameter (only for INPUT_FILE private keys)
    if typ == 'SECRET':
        if command in ('certgen', 'ocspsign', 'crlgen', 'reqgen', 'reqsign', 'sm2sign', 'sm2decrypt', 'sm2exch', 'cmsdecrypt', 'cmssign', 'tlcp_client', 'tlcp_server', 'tls12_client', 'tls12_server', 'tls13_client', 'tls13_server', 'quic_server'):
            if name == 'pass':
                p['credentialKeyParameter'] = 'key'
            elif name == 'exch_pass':
                p['credentialKeyParameter'] = 'exch_key'
        elif command == 'sm9sign' or command == 'sm9decrypt' or command == 'sm9exch':
            if name == 'pass':
                p['credentialKeyParameter'] = 'key'
        elif command == 'sm9keygen':
            if name == 'inpass':
                p['credentialKeyParameter'] = 'in'

    # 3. Evidence-based defaultValue
    if name == 'days' and command in ('certgen', 'reqsign'):
        p['defaultValue'] = 365
        p['recommendation'] = '通用服务器或客户端证书建议 365 天；根CA可设为 3650 或更长。'
        p['formatHint'] = '天数 (1..36500)'
    elif name == 'serial_len' and command in ('certgen', 'reqsign'):
        p['defaultValue'] = 12
        p['formatHint'] = '字节长度 (1..20，缺省12字节高熵随机序列号)'
    elif name == 'outlen':
        if command == 'rand':
            p['defaultValue'] = 32
            p['recommendation'] = '推荐 32 字节生成 256 位安全对称密钥或高熵随机数。'
        elif command == 'sm3_pbkdf2':
            p['defaultValue'] = 32
            p['recommendation'] = 'SM3-PBKDF2 推荐派生 32 字节密钥。'
        elif command == 'api_digest':
            p['recommendation'] = 'SHAKE128/256 可变长摘要必须指定；固定摘要算法禁止填写。'
        elif command in ('api_hkdf', 'api_pbkdf2', 'api_sm3_kdf'):
            p['defaultValue'] = 32
    elif name == 'iter' and command in ('sm3_pbkdf2', 'api_pbkdf2'):
        p['defaultValue'] = 10000
        p['recommendation'] = '密码哈希迭代次数，推荐不低于 10000 次以抵御暴力破解。'
        p['formatHint'] = '整数 (10000..16777215)'
    elif name == 'taglen' and command.endswith(('_gcm', '_ccm')):
        p['defaultValue'] = 16
        p['recommendation'] = 'AEAD 推荐 16 字节完整认证标签以确保最高完整性安全。'
        p['formatHint'] = '字节数 (推荐16，可选4, 8, 12..16)'
    elif name == 'encrypt' and command.startswith('sm4_') and command != 'sm4_cbc_mac':
        p['defaultValue'] = True
        p['recommendation'] = '默认执行加密操作；解密请指定解密参数 (-decrypt)。'
    elif name == 'curve' and command == 'eckeygen':
        p['defaultValue'] = 'secp256r1'
        p['options'] = ENUM_DEFINITIONS['curve']
        p['type'] = 'ENUM'
        p['recommendation'] = '通用 NIST 椭圆曲线，推荐标准 secp256r1 (P-256)。'
    elif name == 'supported_group' and command.startswith(('tlcp', 'tls', 'quic')):
        if command.startswith('tlcp'):
            p['defaultValue'] = 'sm2p256v1'
            p['options'] = ['sm2p256v1']
        elif command.startswith('quic'):
            p['defaultValue'] = 'prime256v1'
            p['options'] = ['prime256v1']
        else:
            p['defaultValue'] = 'sm2p256v1'
            p['options'] = ENUM_DEFINITIONS['supported_group']
        p['type'] = 'ENUM'
    elif name == 'sig_alg' and command.startswith(('tlcp', 'tls', 'quic')):
        if command.startswith('tlcp'):
            p['defaultValue'] = 'sm2sig_sm3'
            p['options'] = ['sm2sig_sm3']
        elif command.startswith(('tls12', 'tls13')):
            p['defaultValue'] = 'sm2sig_sm3'
            p['options'] = ENUM_DEFINITIONS['sig_alg']
        elif command.startswith('quic'):
            p['defaultValue'] = 'ecdsa_secp256r1_sha256'
            p['options'] = ['ecdsa_secp256r1_sha256']
        p['type'] = 'ENUM'
    elif name == 'sig_alg' and command in ('certgen', 'reqgen', 'reqsign', 'crlgen', 'ocspsign'):
        p['defaultValue'] = 'sm2sign-with-sm3'
        p['options'] = ENUM_DEFINITIONS['cert_sig_alg']
        p['type'] = 'ENUM'
        p['recommendation'] = '国密推荐 sm2sign-with-sm3；ECDSA 必须匹配 P-256 密钥。LMS/HSS/XMSS/SPHINCS 属于编译启用的高级签名家族，须匹配原始私钥格式及具体工具大小限制，不表示全部端到端路径已验证。'
    elif name == 'algor' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'ecPublicKey'
        p['options'] = ENUM_DEFINITIONS['algor']
        p['type'] = 'ENUM'
    elif name == 'cipher_suite':
        if command.startswith('tlcp'):
            p['defaultValue'] = 'TLS_ECC_SM4_GCM_SM3'
            p['options'] = ENUM_DEFINITIONS['tlcp_cipher']
        elif command.startswith('tls12'):
            p['defaultValue'] = 'TLS_ECDHE_SM4_GCM_SM3'
            p['options'] = ENUM_DEFINITIONS['tls12_cipher']
        elif command.startswith('tls13'):
            p['defaultValue'] = 'TLS_SM4_GCM_SM3'
            p['options'] = ENUM_DEFINITIONS['tls13_cipher']
        elif command.startswith('quic'):
            p['defaultValue'] = 'TLS_AES_128_GCM_SHA256'
            p['options'] = ENUM_DEFINITIONS['quic_cipher']
        p['type'] = 'ENUM'
    elif name == 'key_usage' and command in ('certgen', 'reqsign'):
        p['options'] = ENUM_DEFINITIONS['key_usage']
        p['type'] = 'ENUM'
        p['formatHint'] = '多选用例下支持重复传入'
    elif name == 'ext_key_usage' and command in ('certgen', 'reqsign'):
        p['options'] = ENUM_DEFINITIONS['ext_key_usage']
        p['type'] = 'ENUM'
        p['formatHint'] = '多选用例下支持重复传入'
    elif name == 'reason' and command == 'certrevoke':
        p['defaultValue'] = 'unspecified'
        p['options'] = ENUM_DEFINITIONS['crl_reason']
        p['type'] = 'ENUM'
    elif name == 'digest' and command in ('ocspreq', 'ocspget', 'sctverify'):
        p['defaultValue'] = 'sm3'
        p['options'] = ENUM_DEFINITIONS['digest_alg']
        p['type'] = 'ENUM'
    elif name == 'lms_type' and command == 'lmskeygen':
        p['defaultValue'] = 'LMS_SM3_M32_H10'
        p['options'] = ENUM_DEFINITIONS['lms_type']
        p['type'] = 'ENUM'
    elif name == 'xmss_type' and command == 'xmsskeygen':
        p['defaultValue'] = 'XMSS_SM3_10_256'
        p['options'] = ENUM_DEFINITIONS['xmss_type']
        p['type'] = 'ENUM'
    elif name == 'xmssmt_type' and command == 'xmssmtkeygen':
        p['defaultValue'] = 'XMSSMT_SM3_20_2_256'
        p['options'] = ENUM_DEFINITIONS['xmssmt_type']
        p['type'] = 'ENUM'
    elif name == 'id' and command.startswith('sm2'):
        p['defaultValue'] = '1234567812345678'
        p['recommendation'] = '国密标准推荐默认身份标识 (IDA = 1234567812345678)。'
    elif name == 'sm2_id' and command in ('certgen', 'reqgen', 'reqsign', 'crlgen', 'ocspsign', 'ocspverify', 'crlverify'):
        p['defaultValue'] = '1234567812345678'
        p['recommendation'] = '国密标准推荐默认签名用户 ID (1234567812345678)。'
    elif name == 'port' and command.endswith(('_server', '_client')):
        p['defaultValue'] = 14435 if command.startswith('tlcp') else (14434 if command.startswith('tls12') else (14433 if command.startswith('tls13') else 14436))
        p['formatHint'] = '端口范围 1024..65535'
    elif name == 'host' and command.endswith('_client'):
        p['defaultValue'] = '127.0.0.1'
        p['formatHint'] = '合法 IPv4/IPv6 或受限域名'
    elif name == 'C' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'CN'
        p['formatHint'] = '2位国家代码，如 CN、US'
    elif name == 'ST' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'Beijing'
    elif name == 'L' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'Haidian'
    elif name == 'O' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'PKU'
    elif name == 'OU' and command in ('certgen', 'reqgen'):
        p['defaultValue'] = 'CS'
    elif name == 'CN' and command in ('certgen', 'reqgen'):
        p['formatHint'] = '通用名称，如 localhost、ROOTCA 或具体域名'

    # Output filenames default suggestions
    if typ == 'OUTPUT_FILE':
        if name == 'out':
            if command.endswith('keygen'): p['defaultValue'] = f'{command}_key.pem'
            elif command in ('certgen', 'reqsign'): p['defaultValue'] = 'cert.pem'
            elif command == 'reqgen': p['defaultValue'] = 'req.pem'
            elif command == 'crlgen': p['defaultValue'] = 'crl.pem'
            elif command.startswith(('sm4', 'zuc', 'api_aes')): p['defaultValue'] = 'cipher.bin'
            elif command.endswith(('sign', 'eia3')): p['defaultValue'] = 'sig.bin'
            elif command.endswith('digest') or command == 'sm3': p['defaultValue'] = 'digest.bin'
            elif command.endswith('hmac'): p['defaultValue'] = 'hmac.bin'
            elif command == 'rand': p['defaultValue'] = 'rand.bin'
        elif name == 'pubout':
            p['defaultValue'] = f'{command}_pub.pem'
        elif name == 'outkey':
            p['defaultValue'] = 'derived_key.bin'

    # Security rule: Never assign constant zero IV or nonce!
    if name in ('iv', 'nonce', 'salt') and p.get('defaultValue') is not None:
        del p['defaultValue']

    # 4. Advanced & Preferred triage
    # Core operational parameters stay in quick view (advanced = False)
    core_names = {'in', 'out', 'key', 'pubkey', 'cert', 'cacert', 'pass', 'inpass', 'outpass', 'CN', 'host', 'port', 'curve', 'alg', 'mode', 'op', 'outlen', 'cipher_suite', 'encrypt', 'decrypt'}
    
    # If a parameter is mandatory (required=True) and has NO defaultValue, it CANNOT be hidden in advanced!
    if p.get('required') and p.get('defaultValue') is None:
        p['advanced'] = False
        p['preferred'] = True
    elif name in core_names or p.get('defaultValue') is not None:
        # Key primary operations
        p['advanced'] = False
        p['preferred'] = name in ('in', 'out', 'key', 'pass', 'CN', 'host', 'port', 'mode', 'curve', 'alg', 'encrypt', 'decrypt')
    else:
        # Optional metadata, verbose, rarely used flags go to advanced
        p['advanced'] = True
        p['preferred'] = False

    # sm4 operational mode flags must be visible in quick view
    if command.startswith('sm4_') and name in ('encrypt', 'decrypt'):
        p['advanced'] = False
        p['preferred'] = True

    # Specific overrides for advanced parameters
    if name in ('verbose', 'hex', 'bin', 'rdrand', 'rdseed', 'sm2_id_hex', 'id_hex', 'peer_id_hex', 'req_sm2_id_hex', 'crl_ldap_uri', 'inhibit_any_policy', 'clock_skew', 'at_least', 'ticket_key', 'psk_key', 'early_data', 'max_early_data_size', 'renegotiation_info', 'renegotiation_info_scsv', 'tls13_change_cipher_spec', 'www', 'alpn', 'trusted_ca_keys', 'verify_depth'):
        p['advanced'] = True
        p['preferred'] = False


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--source-root', default='/tmp/gmssl-review.V5gpYG/upstream')
    args = parser.parse_args()
    root = pathlib.Path(__file__).resolve().parent
    src = pathlib.Path(args.source_root)
    overlays = {o['source_rel']: o for o in runpy.run_path(str(root/'apply-overlays.py'))['OVERLAYS']}
    gmssl_c = (src/'tools/gmssl.c').read_text()
    commands = re.findall(r'extern\s+int\s+([a-z0-9_]+)_main\(', gmssl_c)
    # Deduplicate while preserving order
    seen = set()
    commands = [c for c in commands if not (c in seen or seen.add(c))]
    tools, inventory = [], []

    for command in commands:
        if command in HARDWARE or command in ('help','version'): continue
        source_path = f'tools/{command}.c'
        source_bytes = (src/source_path).read_bytes()
        source = source_bytes.decode('utf-8')
        overlay = overlays.get(source_path)
        if overlay:
            assert hashlib.sha256(source_bytes).hexdigest() == overlay['expected_sha256'], source_path
            for old, new in overlay['replacements']:
                assert source.count(old) == 1, (source_path, old)
                source = source.replace(old, new, 1)
        params = []
        for match in re.finditer(r'!strcmp\(\s*\*argv,\s*"(-[a-zA-Z0-9_]+)"\s*\)', source):
            flag = match.group(1)
            name = flag[1:]
            if any(p['flag'] == flag for p in params): continue
            branch = source[match.end():]
            branch = re.split(r'\}\s*else\s+(?:if|\{)', branch, maxsplit=1)[0]
            takes_value = bool(re.search(r'--argc|\+\+argv', branch))
            typ = 'STRING' if takes_value else 'BOOLEAN'
            if takes_value:
                if name in SECRET: typ = 'SECRET'
                elif name in OUTPUT: typ = 'OUTPUT_FILE'
                elif name in INTEGER: typ = 'INTEGER'
                elif name in HEX or (name == 'key' and command.startswith(('sm4','zuc','sm3_hmac'))): typ = 'HEX'
                elif name in FILES: typ = 'INPUT_FILE'
            line = source[:match.start()].count('\n') + 1
            required = bool(re.search(r'if\s*\(\s*!' + re.escape(name) + r'(?:file)?\s*\)\s*\{[^}]*required', source))
            if name in SECRET and command.endswith('keygen') and command in ('sm2keygen','eckeygen'): required = True
            if name == 'key' and command.startswith(('sm4','zuc','sm3_hmac')): required = True
            if name == 'iv' and command.startswith(('sm4','zuc')): required = True
            p = {'name':name, 'flag':flag, 'label':name, 'type':typ, 'required':required,
                 'description': f'GmSSL {flag}; tools/{command}.c:{line}'}
            if name in RANGES and typ == 'INTEGER': p['min'], p['max'] = RANGES[name]
            if name in ('key','psk_key','ticket_key','h') and typ == 'HEX':
                p['secret'] = True
                p['allowKeyReference'] = True
            if typ == 'SECRET': p['secret'] = True
            if any(s in branch for s in ('_cnt++', '_count++', 'cnt++', 'count++', 'realloc(')):
                p['repeatable'] = True
            params.append(p)

        # Conditional requirements and alternatives are enforced by EngineValidator.
        alternatives = {'sm2verify': {'pubkey','cert'}, 'sm2encrypt': {'pubkey','cert'},
                        'sctverify': {'cert','precert','issuer_key_hash'},
                        'sm2exch': {'cert','pubkey','key','exch_key','secret_state','exch_keyout','keyout','secret_state_out','exch_pass'},
                        'sm9exch': {'key','id','peer_id','exch_key','exch_keyout','keyout'}}
        for p in params:
            if p['name'] in alternatives.get(command, set()): p['required'] = False
            if p['type'] == 'SECRET': p['required'] = command not in ('sm2exch','sm9exch')
            if p['name'] == 'key' and p['type'] == 'INPUT_FILE' and command.endswith('_client'): p['required'] = False
            if command.endswith(('_client','_server')): p['required'] = p['name'] == 'port' or (p['name'] == 'host' and command.endswith('_client'))
        for p in params:
            if p['type'] == 'INPUT_FILE':
                if p['name'] == 'key': p['allowedKeyKinds'] = ['STATEFUL_PRIVATE_KEY'] if command in STATEFUL else ['PRIVATE_KEY']
                elif p['name'] in ('pubkey','peer_pubkey','pubmaster','log_key'): p['allowedKeyKinds'] = ['PUBLIC_KEY']
                elif p['name'] == 'exch_key': p['allowedKeyKinds'] = ['PRIVATE_KEY']
                elif command == 'sm9keygen' and p['name'] == 'in': p['allowedKeyKinds'] = ['MASTER_KEY']
            if p['name'] == 'stage': p.update(type='ENUM', options=['init','respond','confirm','finish'])
            if p['name'] == 'curve': p.update(type='ENUM', options=['secp256r1','secp384r1'])
            if command in ('sm9setup', 'sm9keygen') and p['name'] == 'alg':
                # The OID registry also parses names that this tool cannot execute.
                accepted = list(dict.fromkeys(re.findall(r'case\s+OID_(sm9(?:sign|encrypt|keyagreement))\s*:', source)))
                assert accepted, f'Missing SM9 execution dispatch in {source_path}'
                p.update(type='ENUM', options=accepted)
            if command == 'sm3' and p['name'] == 'in_str': p['secret'] = True
            if p['name'] in ('rdrand','rdseed'): p['description'] += '; disabled unless build enables this CPU feature'

        # Exact protocol option repetition is documented by upstream append-style parsers.
        for p in params:
            if p['name'] in ('sig_alg','supported_group','cipher_suite','key_usage','ext_key_usage','subject_dns_name','subject_ip','issuer_dns_name','rcptcert'):
                p['repeatable'] = True

        # Enrich each parameter with labels, defaults, enums, advanced flag, and credential bindings
        for p in params:
            enrich_parameter(command, p)
            if p['name'] in ('subject_dns_name', 'subject_ip'):
                p.update(type='STRING', repeatable=True)
                p['formatHint'] = ('IPv4 或 IPv6 字面地址，无 zone、CIDR 或域名；DNS/IP 合计最多 64 项，总 DER 最多 2048 字节。'
                    if p['name'] == 'subject_ip' else 'ASCII DNS 名称，单项最多 253 字节；DNS/IP 合计最多 64 项，总 DER 最多 2048 字节。')
                p['recommendation'] = 'reqgen 将 SAN 写入 PKCS9 extensionRequest；reqsign 未显式覆盖时继承已验签 CSR 的 DNS/IP SAN。'
                p['description'] += '; native/apply-overlays.py audited SAN overlay'

        sensitive = command.endswith(('keygen','decrypt','decap','exch')) or command in ('sm9setup','sm9keygen','rand','sm3_pbkdf2','kyberencap')
        operations = ['encrypt','decrypt'] if command.startswith('sm4_') and command not in ('sm4_cbc_mac',) else [command]
        if command in ('sm2exch','sm9exch'): operations = ['init','respond','confirm','finish']
        tool = {'id':command, 'command':command, 'title':command, 'category':category(command),
                'description':f'固定上游 {command}；参数须通过类型与跨参数校验，命令存在不代表全API覆盖。',
                'parameters':params, 'acceptsStdin': bool(re.search(r'\bstdin\b',source)),
                'stdoutMediaType':'application/octet-stream', 'stdoutFilename':command+'.bin',
                'sensitiveOutput':sensitive, 'defaultTimeoutSeconds':30, 'maxTimeoutSeconds':300,
                'adminOnly':category(command)=='protocol' or command in ('crlget','ocspget'), 'stateful':command in STATEFUL,
                'verification':{'status':'implemented', 'evidence':'受控Java获取（严格数字IP与端口白名单、禁止重定向）+ 原生crlparse结果验证' if command == 'crlget' else f'固定源码tools/{command}.c；runner编译完成；尚未逐操作执行验证'}}
        tools.append(tool)
        inventory.append({'command':command, 'scope':'software', 'category':category(command), 'operations':operations,
                          'statefulInput':'key' if command in STATEFUL else None, 'source':f'tools/{command}.c'})

    catalog = {'provider':'gmssl','version':'3.3','sourceCommit':COMMIT,
               'categories':sorted(set(t['category'] for t in tools)), 'tools':tools,
               'coverage':{'registryNames':len(commands), 'businessTools':len(tools), 'excludedHardware':sorted(HARDWARE),
                           'metadata':['help','version'], 'apiOnly':'See native/coverage.md', 'operationVerification':'Per-tool status is not a whole-algorithm certification.'}}
    (root/'catalog.json').write_text(json.dumps(catalog,ensure_ascii=False,indent=2)+'\n')
    (root/'command-inventory.json').write_text(json.dumps(inventory,ensure_ascii=False,indent=2)+'\n')
    # Keep the review matrix reproducible alongside both catalog providers.
    matrix_tools = []
    extensions = json.loads((root/'extensions-catalog.json').read_text())['tools']
    fields = ('name', 'label', 'type', 'required', 'defaultValue', 'options', 'advanced',
              'preferred', 'credentialKeyParameter', 'recommendation', 'formatHint')
    for tool in tools + extensions:
        rows = []
        for p in tool['parameters']:
            row = {field: p.get(field) for field in fields}
            row['classification'] = ('有默认已填 (DEFAULT_PROVIDED)' if p.get('defaultValue') is not None
                else '必填未指定默认 (REQUIRED_USER_INPUT)' if p.get('required')
                else '有选项待选 (ENUM_OPTIONS)' if p.get('options')
                else '可选未指定默认 (OPTIONAL_BLANK)')
            rows.append(row)
        matrix_tools.append({key: tool[key] for key in ('id', 'title', 'category')})
        matrix_tools[-1].update(parameters_count=len(rows), parameters=rows)
    (root/'form-metadata.json').write_text(json.dumps({'totalTools': len(matrix_tools), 'tools': matrix_tools}, ensure_ascii=False, indent=2)+'\n')
    print(f'{len(commands)} registry names, {len(tools)} software tools, {sum(len(t["parameters"]) for t in tools)} parameters')


if __name__ == '__main__':
    main()
