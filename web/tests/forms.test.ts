import { describe, it, expect } from 'vitest'
import { buildParameters, defaults, canManage, canEdit, canRun, validateParameter, isAdvancedParameter, isLinkedPassphraseManaged, getDedicatedKeygenTool, getAllowedAlgorithmIds } from '../src/forms'
import type { User, Project, ManagedFile } from '../src/types'
import { parameter, tool } from './fixtures'
const user:User={id:'u',username:'tester',role:'USER'},project:Project={id:'p',name:'Project',role:'VIEWER',createdAt:''}
describe('typed dynamic parameter validation',()=>{
 it('validates required, integer, enum and hex constraints',()=>{
  expect(validateParameter(parameter({required:true}), '')).toBeTruthy()
  for(const value of ['1.2',2**54,0,4])expect(validateParameter(parameter({type:'INTEGER',min:1,max:3}),value)).toBeTruthy()
  expect(validateParameter(parameter({type:'INTEGER',min:1,max:3}),'2')).toBeUndefined()
  expect(validateParameter(parameter({type:'ENUM',options:['SM3']}),'MD5')).toBeTruthy()
  for(const value of ['a','gg','key:bad'])expect(validateParameter(parameter({type:'HEX'}),value)).toBeTruthy()
  expect(validateParameter(parameter({type:'HEX'}),'00aB')).toBeUndefined()
 })
 it('only accepts basename outputs and declared input references',()=>{
  for(const value of ['../key','/etc/passwd','a/b','a\\b','..','a\n.txt'])expect(validateParameter(parameter({type:'OUTPUT_FILE'}),value)).toBeTruthy()
  expect(validateParameter(parameter({type:'OUTPUT_FILE'}),'key.pem')).toBeUndefined()
  const reference='key:12345678-1234-1234-1234-123456789abc'
  expect(validateParameter(parameter({type:'INPUT_FILE'}),reference)).toBeTruthy()
  expect(validateParameter(parameter({type:'INPUT_FILE',allowedKeyKinds:['PRIVATE_KEY']}),reference)).toBeUndefined()
  expect(validateParameter(parameter({type:'HEX'}),reference)).toBeTruthy()
  expect(validateParameter(parameter({type:'HEX',allowKeyReference:true}),reference)).toBeUndefined()
 })
 it('stateful signing rejects temporary files',()=>{
  const definition=tool({stateful:true,parameters:[parameter({type:'INPUT_FILE',name:'key',allowedKeyKinds:['STATEFUL_PRIVATE_KEY'],required:true})]});expect(buildParameters(definition,{key:'file:12345678-1234-1234-1234-123456789abc'}).errors.key).toBeTruthy()
 })
 it('never prepopulates secret values including HEX and repeated secrets',()=>{
  const definition=tool({parameters:[parameter({name:'a',type:'SECRET',defaultValue:'never'}),parameter({name:'b',type:'HEX',secret:true,defaultValue:'abcd'}),parameter({name:'c',secret:true,repeatable:true,defaultValue:['never']})]})
  expect(defaults(definition)).toEqual({a:'',b:'',c:[]})
 })
 it('builds only declared parameters and serializes repeated typed values',()=>{
  const definition=tool({parameters:[parameter({name:'n',type:'INTEGER',repeatable:true,required:true}),parameter({name:'flag',type:'BOOLEAN'}),parameter({name:'empty'})]})
  expect(buildParameters(definition,{n:['1','2'],flag:false,empty:'',argv:'bad'})).toEqual({parameters:{n:[1,2],flag:false},errors:{}})
  expect(buildParameters(definition,{n:[]} ).errors.n).toBeTruthy()
  expect(buildParameters(definition,{n:'1'} ).errors.n).toBeTruthy()
 })
 it('enforces SM4 encrypt and decrypt mutually exclusive selection and defaults to encrypt',()=>{
  const sm4Def=tool({id:'sm4_ecb',command:'sm4_ecb',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',type:'HEX',required:true,secret:true})]})
  const defs=defaults(sm4Def)
  expect(defs.encrypt).toBe(true)
  expect(defs.decrypt).toBe(false)
  const validRes=buildParameters(sm4Def,{encrypt:true,decrypt:false,key:'0123456789abcdeffedcba9876543210'})
  expect(validRes.errors).toEqual({})
  const bothRes=buildParameters(sm4Def,{encrypt:true,decrypt:true,key:'0123456789abcdeffedcba9876543210'})
  expect(bothRes.errors.encrypt).toContain('互斥操作')
  expect(bothRes.errors.decrypt).toContain('互斥操作')
  const neitherRes=buildParameters(sm4Def,{encrypt:false,decrypt:false,key:'0123456789abcdeffedcba9876543210'})
  expect(neitherRes.errors.encrypt).toContain('请选择操作模式')
 })
 it('validates exact SM4 key lengths and bypasses vault references',()=>{
  const sm4Tool=tool({id:'sm4_cbc',command:'sm4_cbc',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  const xtsTool=tool({id:'sm4_xts',command:'sm4_xts',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  expect(buildParameters(sm4Tool,{encrypt:true,decrypt:false,key:'0123456789abcdef'}).errors.key).toContain('16 字节（32 位十六进制字符）')
  expect(buildParameters(sm4Tool,{encrypt:true,decrypt:false,key:'0123456789abcdeffedcba9876543210'}).errors.key).toBeUndefined()
  expect(buildParameters(xtsTool,{encrypt:true,decrypt:false,key:'0123456789abcdeffedcba9876543210'}).errors.key).toContain('32 字节（64 位十六进制字符）')
  expect(buildParameters(xtsTool,{encrypt:true,decrypt:false,key:'0123456789abcdeffedcba98765432100123456789abcdeffedcba9876543210'}).errors.key).toBeUndefined()
  expect(buildParameters(sm4Tool,{encrypt:true,decrypt:false,key:'key:12345678-1234-1234-1234-123456789abc'}).errors.key).toBeUndefined()
 })
 it('defaults pkcs7_padding to true for sm4_cbc and sm4_ecb when declared', () => {
  const cbcTool = tool({id:'sm4_cbc',command:'sm4_cbc',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'pkcs7_padding',type:'BOOLEAN'}),parameter({name:'key',type:'HEX'})]})
  const defs = defaults(cbcTool)
  expect(defs.pkcs7_padding).toBe(true)
  expect(defs.encrypt).toBe(true)
  expect(defs.decrypt).toBe(false)
  const nonSm4Tool = tool({id:'sm3',command:'sm3',parameters:[parameter({name:'pkcs7_padding',type:'BOOLEAN'})]})
  expect(defaults(nonSm4Tool).pkcs7_padding).toBe(false)
 })
 it('correctly classifies advanced parameters and never hides required fields without default', () => {
  const optionalNoDefault = parameter({name:'opt', advanced:true, required:false})
  expect(isAdvancedParameter(optionalNoDefault)).toBe(true)

  const requiredWithDefault = parameter({name:'req_def', advanced:true, required:true, defaultValue:'sm3'})
  expect(isAdvancedParameter(requiredWithDefault)).toBe(true)

  const requiredNoDefault = parameter({name:'req_nodef', advanced:true, required:true})
  expect(isAdvancedParameter(requiredNoDefault)).toBe(false)

  const basicParam = parameter({name:'basic', advanced:false, required:true})
  expect(isAdvancedParameter(basicParam)).toBe(false)
 })
 it('identifies managed linked passphrase and exempts required passphrase validation', () => {
  const keyId = '11111111-2222-3333-4444-555555555555'
  const managedKey = {
    id: keyId,
    projectId: 'p',
    name: 'Managed-SM2',
    algorithm: 'SM2',
    keyKind: 'PRIVATE_KEY',
    encoding: 'PEM',
    validationStatus: 'VALIDATED',
    createdAt: '',
    updatedAt: '',
    stateful: false,
    hasManagedPassphrase: true
  }
  const legacyKey = {
    ...managedKey,
    id: '22222222-2222-3333-4444-555555555555',
    hasManagedPassphrase: false
  }

  const passParam = parameter({
    name: 'pass',
    type: 'SECRET',
    required: true,
    secret: true,
    credentialKeyParameter: 'key'
  })

  expect(isLinkedPassphraseManaged(passParam, { key: `key:${keyId}` }, [managedKey])).toBe(true)
  expect(isLinkedPassphraseManaged(passParam, { key: `key:${legacyKey.id}` }, [legacyKey])).toBe(false)
  expect(isLinkedPassphraseManaged(passParam, { key: 'file:file-123' }, [managedKey])).toBe(false)

  const signTool = tool({
    id: 'sm2sign',
    command: 'sm2sign',
    parameters: [
      parameter({ name: 'key', type: 'INPUT_FILE', required: true, allowedKeyKinds: ['PRIVATE_KEY'] }),
      passParam
    ]
  })

  // When linked key has managed passphrase, omitting pass produces no error
  const resManaged = buildParameters(signTool, { key: `key:${keyId}`, pass: '' }, [managedKey])
  expect(resManaged.errors.pass).toBeUndefined()

  // When linked key does not have managed passphrase, omitting pass produces required error
  const resLegacy = buildParameters(signTool, { key: `key:${legacyKey.id}`, pass: '' }, [legacyKey])
  expect(resLegacy.errors.pass).toBe('此项为必填')

  // When linked file has managed passphrase, omitting pass also produces no error
  const managedFile: ManagedFile = {
    id: '11111111-1111-4111-8111-111111111111',
    name: 'temp-key.pem',
    size: 256,
    mediaType: 'application/x-pem-file',
    temporary: true,
    createdAt: '',
    hasManagedPassphrase: true
  }
  const regularFile: ManagedFile = {
    ...managedFile,
    id: '22222222-2222-4222-8222-222222222222',
    hasManagedPassphrase: false
  }

  expect(isLinkedPassphraseManaged(passParam, { key: `file:${managedFile.id}` }, [], [managedFile])).toBe(true)
  expect(isLinkedPassphraseManaged(passParam, { key: `file:${regularFile.id}` }, [], [regularFile])).toBe(false)

  const resFileManaged = buildParameters(signTool, { key: `file:${managedFile.id}`, pass: '' }, [], [managedFile])
  expect(resFileManaged.errors).toEqual({})

  const resFileRegular = buildParameters(signTool, { key: `file:${regularFile.id}`, pass: '' }, [], [regularFile])
  expect(resFileRegular.errors.pass).toBe('此项为必填')
 })

 it('routes dedicated keygen tools without offering generic keygen', () => {
  const pIn = parameter({ name: 'in', type: 'INPUT_FILE', allowedKeyKinds: ['MASTER_KEY'] })
  expect(getDedicatedKeygenTool('sm9keygen', pIn)).toEqual({ targetTool: 'sm9setup', label: 'SM9 主密钥 (sm9setup)' })

  const pKey = parameter({ name: 'key', type: 'INPUT_FILE', allowedKeyKinds: ['PRIVATE_KEY'] })
  expect(getDedicatedKeygenTool('sm9sign', pKey)).toEqual({ targetTool: 'sm9keygen', label: 'SM9 私钥 (sm9keygen)' })

  const pPub = parameter({ name: 'pubmaster', type: 'INPUT_FILE', allowedKeyKinds: ['PUBLIC_KEY'] })
  expect(getDedicatedKeygenTool('sm9verify', pPub)).toEqual({ targetTool: 'sm9setup', label: 'SM9 主公钥 (sm9setup)' })

  const pStateful = parameter({ name: 'key', type: 'INPUT_FILE', allowedKeyKinds: ['STATEFUL_PRIVATE_KEY'] })
  expect(getDedicatedKeygenTool('lmssign', pStateful)).toEqual({ targetTool: 'lmskeygen', label: 'LMS 状态私钥 (lmskeygen)' })
  expect(getDedicatedKeygenTool('hsssign', pStateful)).toEqual({ targetTool: 'hsskeygen', label: 'HSS 状态私钥 (hsskeygen)' })
  expect(getDedicatedKeygenTool('xmsssign', pStateful)).toEqual({ targetTool: 'xmsskeygen', label: 'XMSS 状态私钥 (xmsskeygen)' })
  expect(getDedicatedKeygenTool('xmssmtsign', pStateful)).toEqual({ targetTool: 'xmssmtkeygen', label: 'XMSSMT 状态私钥 (xmssmtkeygen)' })

  expect(getDedicatedKeygenTool('sphincssign', pKey)).toEqual({ targetTool: 'sphincskeygen', label: 'SPHINCS+ 密钥 (sphincskeygen)' })
  expect(getDedicatedKeygenTool('kyberencap', parameter({ name: 'pubkey', type: 'INPUT_FILE' }))).toEqual({ targetTool: 'kyberkeygen', label: 'Kyber 密钥 (kyberkeygen)' })

  // Generic tools return null
  expect(getDedicatedKeygenTool('sm4_cbc', parameter({ name: 'key', type: 'HEX' }))).toBeNull()
  expect(getDedicatedKeygenTool('sm2sign', pKey)).toBeNull()
 })

 it('strictly filters allowed algorithms per tool and parameter', () => {
  expect(getAllowedAlgorithmIds('sm4_cbc')).toEqual(['SM4'])
  expect(getAllowedAlgorithmIds('sm4_xts')).toEqual(['SM4-XTS'])
  expect(getAllowedAlgorithmIds('aes_cbc')).toEqual(['AES'])
  expect(getAllowedAlgorithmIds('zuc')).toEqual(['ZUC'])
  expect(getAllowedAlgorithmIds('zuc256')).toEqual(['ZUC256'])
  expect(getAllowedAlgorithmIds('hmac')).toEqual(['HMAC'])

  expect(getAllowedAlgorithmIds('sm2sign')).toEqual(['SM2'])
  expect(getAllowedAlgorithmIds('tlcp_client')).toEqual(['SM2'])
  expect(getAllowedAlgorithmIds('eckeygen')).toEqual(['P-256', 'P-384'])
  expect(getAllowedAlgorithmIds('tls12_client')).toEqual(['SM2', 'P-256', 'P-384'])
  expect(getAllowedAlgorithmIds('certgen')).toEqual(['SM2', 'P-256', 'P-384'])

  // Dedicated/unsupported tools return empty array
  expect(getAllowedAlgorithmIds('sm9sign')).toEqual([])
  expect(getAllowedAlgorithmIds('lmssign')).toEqual([])
  expect(getAllowedAlgorithmIds(undefined, parameter({ allowedKeyKinds: ['STATEFUL_PRIVATE_KEY'] }))).toEqual([])
  expect(getAllowedAlgorithmIds(undefined, parameter({ allowedKeyKinds: ['MASTER_KEY'] }))).toEqual([])
 })
})
describe('role boundaries',()=>{
 it('requires user and project even for admin',()=>{
  expect(canEdit(null,project)).toBe(false)
  expect(canEdit({...user,role:'ADMIN'},undefined)).toBe(false)
 })
 it('viewer has no edit, owner manages, editor runs ordinary tools',()=>{
  expect(canEdit(user,project)).toBe(false);expect(canManage(user,project)).toBe(false)
  expect(canManage(user,{...project,role:'OWNER'})).toBe(true)
  expect(canRun(user,{...project,role:'EDITOR'},tool())).toBe(true)
  expect(canManage(user,{...project,role:'EDITOR'})).toBe(false)
 })
 it('restricts administrative protocols and unavailable capabilities',()=>{
  expect(canRun(user,{...project,role:'OWNER'},tool({adminOnly:true}))).toBe(false)
  expect(canRun({...user,role:'ADMIN'},project,tool({adminOnly:true}))).toBe(true)
  expect(canRun({...user,role:'ADMIN'},project,tool({verification:{status:'unavailable',evidence:'not ready'}}))).toBe(false)
 })
})
