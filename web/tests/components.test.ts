import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import ParameterField from '../src/components/ParameterField.vue'
import ToolForm from '../src/components/ToolForm.vue'
import KeyGenerateDialog from '../src/components/KeyGenerateDialog.vue'
import * as api from '../src/api'
import { parameter, tool } from './fixtures'
describe('form components',()=>{
 it('masks a secret HEX and uses escaped text labels',()=>{
  const wrapper=mount(ParameterField,{props:{parameter:parameter({type:'HEX',secret:true,label:'<img src=x>'}),modelValue:'',keys:[],files:[]}})
  expect(wrapper.find('input').attributes('type')).toBe('password');expect(wrapper.find('img').exists()).toBe(false)
 })
 it('renders declared enum options and emits boolean values',async()=>{
  const checkbox=mount(ParameterField,{props:{parameter:parameter({type:'BOOLEAN'}),modelValue:false,keys:[],files:[]}})
  await checkbox.get('input').setValue(true);expect(checkbox.emitted('update:modelValue')?.[0]).toEqual([true])
  const select=mount(ParameterField,{props:{parameter:parameter({type:'ENUM',options:['SM3','SHA256']}),modelValue:'',keys:[],files:[]}})
  expect(select.findAll('option').map(o=>o.text())).toEqual(['请选择','SM3','SHA256'])
 })
 it('submits typed values, raw stdin and clears secret input',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool({parameters:[parameter({type:'SECRET',required:true,name:'pass'})]}),keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('input[type=password]').setValue('do-not-save');await wrapper.get('textarea').setValue('abc');await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toEqual([{toolId:'test',parameters:{pass:'do-not-save'},stdinText:'abc',timeoutSeconds:30}]);expect((wrapper.get('input[type=password]').element as HTMLInputElement).value).toBe('')
 })
 it('rejects invalid form without network event and honors disabled permissions',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool({parameters:[parameter({type:'HEX',required:true})]}),keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('form').trigger('submit.prevent');expect(wrapper.emitted('run')).toBeUndefined();expect(wrapper.text()).toContain('此项为必填')
 })
 it('prevents even programmatic submit when view permissions disable execution',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool(),keys:[],files:[],disabled:true,busy:false}});expect(wrapper.get('fieldset').attributes('disabled')).toBeDefined();await wrapper.get('form').trigger('submit.prevent');expect(wrapper.emitted('run')).toBeUndefined()
 })
 it('supports repeated parameters and stdin file mutually exclusive with text',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool({parameters:[parameter({type:'INTEGER',repeatable:true,name:'n'})]}),keys:[],files:[{id:'12345678-1234-1234-1234-123456789abc',name:'abc.txt',size:3,mediaType:'text/plain',createdAt:''}],disabled:false,busy:false}})
  await wrapper.findAll('button').find(b=>b.text().includes('添加参数'))!.trigger('click');await wrapper.get('input[aria-label="参数"]').setValue('5');await wrapper.get('textarea').setValue('old text');await wrapper.findAll('button').find(b=>b.text()==='项目文件')!.trigger('click');await wrapper.get('select').setValue('file:12345678-1234-1234-1234-123456789abc');await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toEqual([{toolId:'test',parameters:{n:[5]},stdinFileRef:'file:12345678-1234-1234-1234-123456789abc',timeoutSeconds:30}])
 })
 it('emits upload event with temporary:true by default for parameter file upload',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool({parameters:[parameter({type:'INPUT_FILE',name:'in'})]}),keys:[],files:[],disabled:false,busy:false}})
  const fileInput=wrapper.get('.file-upload-actions input[type=file]')
  const fakeFile=new File(['hello'],'input.txt',{type:'text/plain'})
  Object.defineProperty(fileInput.element,'files',{value:[fakeFile]})
  await fileInput.trigger('change')
  expect(wrapper.emitted('upload')?.[0]).toEqual([{file:fakeFile,temporary:true,parameter:'in',index:undefined}])
 })
 it('emits upload event with temporary:true by default for stdin file upload',async()=>{
  const wrapper=mount(ToolForm,{props:{tool:tool({acceptsStdin:true}),keys:[],files:[],disabled:false,busy:false}})
  await wrapper.findAll('button').find(b=>b.text()==='项目文件')!.trigger('click')
  const fileInput=wrapper.get('.section-line .file-upload-actions input[type=file]')
  const fakeFile=new File(['stdin'],'stdin.txt',{type:'text/plain'})
  Object.defineProperty(fileInput.element,'files',{value:[fakeFile]})
  await fileInput.trigger('change')
  expect(wrapper.emitted('upload')?.[0]).toEqual([{file:fakeFile,temporary:true,isStdin:true}])
 })
 it('generates random SM4 key on button click and toggles visibility',async()=>{
  const sm4Tool=tool({id:'sm4_cbc',title:'SM4 CBC',parameters:[parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  const genBtn=wrapper.findAll('button').find(b=>b.text()==='随机生成密钥')
  expect(genBtn).toBeDefined()
  await genBtn!.trigger('click')
  const input=wrapper.get('input[type=password]')
  const val=(input.element as HTMLInputElement).value
  expect(val).toMatch(/^[0-9a-f]{32}$/)
  expect(wrapper.text()).toContain('已生成 128 位随机密钥（仅填入当前表单，未在密钥库托管；解密请自行妥善保留同一密钥）')
  expect(wrapper.findAll('button').find(b=>b.text()==='覆盖生成随机密钥')).toBeDefined()
  const revealBtn=wrapper.findAll('button').find(b=>b.text()==='显示')
  expect(revealBtn).toBeDefined()
  await revealBtn!.trigger('click')
  expect(wrapper.find('input[type=text]').exists()).toBe(true)
  await wrapper.findAll('button').find(b=>b.text()==='隐藏')!.trigger('click')
  expect(wrapper.find('input[type=password]').exists()).toBe(true)
 })
 it('supports selecting AES key bit-length before generation',async()=>{
  const aesTool=tool({id:'aes_128_cbc',title:'AES CBC',parameters:[parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  const wrapper=mount(ToolForm,{props:{tool:aesTool,keys:[],files:[],disabled:false,busy:false}})
  const select=wrapper.get('select[aria-label="密钥长度"]')
  expect(select).toBeDefined()
  await select.setValue(256)
  await wrapper.findAll('button').find(b=>b.text()==='随机生成密钥')!.trigger('click')
  const input=wrapper.get('input[type=password]')
  const val=(input.element as HTMLInputElement).value
  expect(val).toMatch(/^[0-9a-f]{64}$/)
  expect(wrapper.text()).toContain('已生成 256 位随机密钥')
 })
 it('displays field error when browser crypto source is unavailable',async()=>{
  const sm4Tool=tool({id:'sm4_cbc',title:'SM4 CBC',parameters:[parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  const originalCrypto=globalThis.crypto
  // @ts-expect-error test override
  delete globalThis.crypto
  try{
    const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
    await wrapper.findAll('button').find(b=>b.text()==='随机生成密钥')!.trigger('click')
    expect(wrapper.text()).toContain('浏览器随机源不可用')
  }finally{
    Object.defineProperty(globalThis,'crypto',{value:originalCrypto,configurable:true})
  }
 })
 it('manages SM4 operation mode radios and allows empty text stdin with exact block size or padding',async()=>{
  const sm4Tool=tool({id:'sm4_ecb',command:'sm4_ecb',title:'SM4 ECB',acceptsStdin:true,parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true}),parameter({name:'in',flag:'-in',type:'INPUT_FILE'})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  const encRadio=wrapper.get('input[type=radio][value=encrypt]')
  const decRadio=wrapper.get('input[type=radio][value=decrypt]')
  expect((encRadio.element as HTMLInputElement).checked).toBe(true)
  expect((decRadio.element as HTMLInputElement).checked).toBe(false)
  await decRadio.setValue(true)
  expect((encRadio.element as HTMLInputElement).checked).toBe(false)
  expect((decRadio.element as HTMLInputElement).checked).toBe(true)
  await wrapper.get('input[type=password]').setValue('0123456789abcdeffedcba9876543210')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toEqual([{
    toolId:'sm4_ecb',
    parameters:{decrypt:true,encrypt:false,key:'0123456789abcdeffedcba9876543210'},
    stdinText:'',
    timeoutSeconds:30
  }])
 })
 it('preserves exact stdin whitespace without trimming',async()=>{
  const sm4Tool=tool({id:'sm4_ecb',command:'sm4_ecb',title:'SM4 ECB',acceptsStdin:true,parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true}),parameter({name:'in',flag:'-in',type:'INPUT_FILE'})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('input[type=password]').setValue('0123456789abcdeffedcba9876543210')
  // 16 bytes exact
  await wrapper.get('textarea').setValue('0123456789abcdef')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toEqual([{
    toolId:'sm4_ecb',
    parameters:{decrypt:false,encrypt:true,key:'0123456789abcdeffedcba9876543210'},
    stdinText:'0123456789abcdef',
    timeoutSeconds:30
  }])
 })
 it('intercepts non-16-byte multiple input for sm4_ecb with clear chinese error',async()=>{
  const sm4Tool=tool({id:'sm4_ecb',command:'sm4_ecb',title:'SM4 ECB',acceptsStdin:true,parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true}),parameter({name:'in',flag:'-in',type:'INPUT_FILE'})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('input[type=password]').setValue('0123456789abcdeffedcba9876543210')
  // 5 bytes: not a multiple of 16
  await wrapper.get('textarea').setValue('hello')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.text()).toContain('SM4 ECB 模式无填充，输入长度须为 16 字节整数倍（当前为 5 字节）')
  expect(wrapper.emitted('run')).toBeUndefined()
  // provide 32 bytes: multiple of 16
  await wrapper.get('textarea').setValue('0123456789abcdef0123456789abcdef')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toBeDefined()
 })
 it('reports error when SM4 file mode is chosen without selecting input file or stdin file',async()=>{
  const sm4Tool=tool({id:'sm4_ecb',command:'sm4_ecb',title:'SM4 ECB',acceptsStdin:true,parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true}),parameter({name:'in',flag:'-in',type:'INPUT_FILE'})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('input[type=password]').setValue('0123456789abcdeffedcba9876543210')
  await wrapper.findAll('button').find(b=>b.text()==='项目文件')!.trigger('click')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.text()).toContain('请选择输入文件 (-in) 或在下方选择项目文件作为标准输入')
 })
 it('does not require input file for tools with in_str like sm3',async()=>{
  const sm3Tool=tool({id:'sm3',command:'sm3',title:'SM3',acceptsStdin:true,parameters:[parameter({name:'in_str',label:'in_str',flag:'-in_str',type:'STRING'}),parameter({name:'in',flag:'-in',type:'INPUT_FILE'})]})
  const wrapper=mount(ToolForm,{props:{tool:sm3Tool,keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('input[aria-label="in_str"]').setValue('abc')
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.emitted('run')?.[0]).toEqual([{
    toolId:'sm3',
    parameters:{in_str:'abc'},
    stdinText:'',
    timeoutSeconds:30
  }])
 })
 it('clears required key validation error immediately when random key is generated',async()=>{
  const sm4Tool=tool({id:'sm4_cbc',command:'sm4_cbc',title:'SM4 CBC',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true,allowKeyReference:true})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.text()).toContain('此项为必填')
  expect(wrapper.emitted('run')).toBeUndefined()
  const genBtn=wrapper.findAll('button').find(b=>b.text()==='随机生成密钥')
  expect(genBtn).toBeDefined()
  await genBtn!.trigger('click')
  expect(wrapper.text()).not.toContain('此项为必填')
  expect(wrapper.text()).toContain('已生成 128 位随机密钥')
 })
 it('defaults pkcs7_padding toggle to checked for sm4_cbc and allows unchecking',async()=>{
  const sm4Tool=tool({id:'sm4_cbc',command:'sm4_cbc',title:'SM4 CBC',parameters:[parameter({name:'encrypt',type:'BOOLEAN'}),parameter({name:'decrypt',type:'BOOLEAN'}),parameter({name:'pkcs7_padding',type:'BOOLEAN',label:'pkcs7_padding',flag:'-pkcs7_padding'}),parameter({name:'key',flag:'-key',type:'HEX',required:true,secret:true})]})
  const wrapper=mount(ToolForm,{props:{tool:sm4Tool,keys:[],files:[],disabled:false,busy:false}})
  expect(wrapper.text()).toContain('PKCS#7 填充（普通文本建议开启）')
  const checkbox=wrapper.get('input[type=checkbox]')
  expect((checkbox.element as HTMLInputElement).checked).toBe(true)
  await checkbox.setValue(false)
  expect((checkbox.element as HTMLInputElement).checked).toBe(false)
 })
 it('toggles advanced parameters visibility and preserves required parameters without default',async()=>{
  const advancedTool = tool({
    id: 'advanced_tool',
    parameters: [
      parameter({ name: 'basic_field', label: '基础参数', type: 'STRING', required: true }),
      parameter({ name: 'adv_opt', label: '高级可选参数', type: 'STRING', advanced: true, required: false }),
      parameter({ name: 'adv_req_nodef', label: '高级必填无默认', type: 'STRING', advanced: true, required: true })
    ]
  })
  const wrapper = mount(ToolForm, { props: { tool: advancedTool, keys: [], files: [], disabled: false, busy: false } })
  // adv_opt is folded by default; adv_req_nodef must stay visible because it has no default
  expect(wrapper.text()).toContain('基础参数')
  expect(wrapper.text()).toContain('高级必填无默认')
  expect(wrapper.text()).not.toContain('高级可选参数')
  expect(wrapper.text()).toContain('展开高级参数 (含 1 项)')

  // Click toggle to expand
  const toggleBtn = wrapper.find('.mode-toggle-button')
  expect(toggleBtn.exists()).toBe(true)
  await toggleBtn.trigger('click')

  expect(wrapper.text()).toContain('高级可选参数')
  expect(wrapper.text()).toContain('折叠高级参数')

  // Click toggle again to fold
  await toggleBtn.trigger('click')
  expect(wrapper.text()).not.toContain('高级可选参数')
 })
 it('displays managed passphrase notice and bypasses password requirement when key hasManagedPassphrase',async()=>{
  const keyId = '11111111-2222-3333-4444-555555555555'
  const managedKey = {
    id: keyId,
    projectId: 'p1',
    name: 'Managed-Sign-Key',
    algorithm: 'SM2',
    keyKind: 'PRIVATE_KEY',
    encoding: 'PEM',
    validationStatus: 'VALIDATED',
    createdAt: '',
    updatedAt: '',
    stateful: false,
    hasManagedPassphrase: true
  }
  const signTool = tool({
    id: 'sm2sign',
    acceptsStdin: true,
    parameters: [
      parameter({ name: 'key', label: '签名私钥', type: 'INPUT_FILE', required: true, allowedKeyKinds: ['PRIVATE_KEY'] }),
      parameter({ name: 'pass', label: '私钥口令', type: 'SECRET', required: true, secret: true, credentialKeyParameter: 'key' })
    ]
  })

  const wrapper = mount(ToolForm, {
    props: {
      tool: signTool,
      keys: [managedKey],
      files: [],
      disabled: false,
      busy: false,
      projectId: 'p1'
    }
  })

  // Initially without key selected, selecting submit shows required error
  await wrapper.get('form').trigger('submit.prevent')
  expect(wrapper.text()).toContain('此项为必填')

  // Select the managed key
  const keySelect = wrapper.get('select[aria-label="签名私钥"]')
  await keySelect.setValue(`key:${keyId}`)

  // Managed passphrase banner should appear
  expect(wrapper.text()).toContain('已关联托管密钥私钥口令：平台将自动安全注入，无需手输')

  // Submit without entering password
  await wrapper.get('textarea').setValue('hello sm2')
  await wrapper.get('form').trigger('submit.prevent')

  // Form succeeds and emits run event!
  expect(wrapper.emitted('run')).toBeDefined()
  const emittedRun = wrapper.emitted('run')?.[0]?.[0] as Record<string, unknown>
  expect(emittedRun.toolId).toBe('sm2sign')
  expect((emittedRun.parameters as Record<string, unknown>)['key']).toBe(`key:${keyId}`)
 })
 it('KeyGenerateDialog renders dual providers and handles key generation flow',async()=>{
  const capsSpy = vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
    providers: [
      { id: 'gmssl', available: true, version: '3.3', algorithms: ['SM4', 'SM2'] },
      { id: 'openssl', available: true, version: '3.0', algorithms: ['SM4', 'EC'] }
    ],
    algorithms: [
      { id: 'SM4', kind: 'SYMMETRIC_KEY', bits: [128], curves: [], providers: ['gmssl', 'openssl'] },
      { id: 'SM2', kind: 'PRIVATE_KEY', bits: [], curves: ['sm2'], providers: ['gmssl'] },
      { id: 'EC', kind: 'PRIVATE_KEY', bits: [], curves: ['secp256r1', 'secp384r1'], providers: ['gmssl', 'openssl'] }
    ]
  })
  const generateSpy = vi.spyOn(api, 'generateKey').mockResolvedValue({
    provider: 'gmssl',
    algorithm: 'SM4',
    storage: 'MANAGED',
    reference: 'key:99999999-8888-7777-6666-555555555555',
    warnings: []
  })

  const wrapper = mount(KeyGenerateDialog, {
    props: {
      visible: true,
      projectId: 'proj-123'
    }
  })
  await flushPromises()

  expect(wrapper.text()).toContain('生成加密密钥材料')
  expect(wrapper.text()).toContain('GmSSL 原生密码引擎')
  expect(wrapper.text()).toContain('OpenSSL 安全引擎')
  expect(wrapper.text()).toContain('加密托管至项目密钥库')

  // Submit form to generate key
  await wrapper.get('form').trigger('submit.prevent')

  expect(generateSpy).toHaveBeenCalledWith('proj-123', expect.objectContaining({
    provider: 'gmssl',
    algorithm: 'SM4',
    storage: 'MANAGED',
    bits: 128
  }))

  expect(wrapper.emitted('generated')?.[0]?.[0]).toEqual(expect.objectContaining({
    reference: 'key:99999999-8888-7777-6666-555555555555'
  }))
  expect(wrapper.emitted('update:visible')?.[0]).toEqual([false])

  generateSpy.mockRestore()
  capsSpy.mockRestore()
 })

 it('KeyGenerateDialog handles capability loading failure gracefully by disabling inputs and showing error', async () => {
  const capsSpy = vi.spyOn(api, 'getKeyGenCapabilities').mockRejectedValue(new Error('Engine unavailable'))

  const wrapper = mount(KeyGenerateDialog, {
    props: {
      visible: true,
      projectId: 'proj-123'
    }
  })
  await flushPromises()

  expect(wrapper.text()).toContain('获取密钥生成能力失败：Engine unavailable')
  expect(wrapper.find('form').exists()).toBe(false)

  capsSpy.mockRestore()
 })

 it('KeyGenerateDialog generates ZUC256 with exact uppercase payload without hyphens', async () => {
  const capsSpy = vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
    providers: [{ id: 'gmssl', available: true, version: '3.3', algorithms: ['ZUC256'] }],
    algorithms: [{ id: 'ZUC256', kind: 'SYMMETRIC_KEY', bits: [256], curves: [], providers: ['gmssl'] }]
  })
  const generateSpy = vi.spyOn(api, 'generateKey').mockResolvedValue({
    provider: 'gmssl',
    algorithm: 'ZUC256',
    storage: 'MANAGED',
    reference: 'key:zuc-123',
    warnings: []
  })

  const wrapper = mount(KeyGenerateDialog, {
    props: {
      visible: true,
      projectId: 'proj-123',
      toolId: 'zuc256'
    }
  })
  await flushPromises()

  await wrapper.get('form').trigger('submit.prevent')

  expect(generateSpy).toHaveBeenCalledWith('proj-123', expect.objectContaining({
    provider: 'gmssl',
    algorithm: 'ZUC256',
    bits: 256
  }))

  generateSpy.mockRestore()
  capsSpy.mockRestore()
 })

 it('KeyGenerateDialog generates NIST curves sending algorithm: "EC" and curve: "secp256r1" or "secp384r1"', async () => {
  const capsSpy = vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
    providers: [{ id: 'openssl', available: true, version: '3.0', algorithms: ['EC'] }],
    algorithms: [{ id: 'EC', kind: 'PRIVATE_KEY', bits: [], curves: ['secp256r1', 'secp384r1'], providers: ['openssl'] }]
  })
  const generateSpy = vi.spyOn(api, 'generateKey').mockResolvedValue({
    provider: 'openssl',
    algorithm: 'EC',
    storage: 'MANAGED',
    reference: 'key:ec-123',
    warnings: []
  })

  const wrapper = mount(KeyGenerateDialog, {
    props: {
      visible: true,
      projectId: 'proj-123',
      toolId: 'eckeygen'
    }
  })
  await flushPromises()

  // Algorithm select should have P-256 and P-384
  const options = wrapper.findAll('select[aria-label="算法选择"] option').map(o => o.attributes('value'))
  expect(options).toContain('P-256')
  expect(options).toContain('P-384')

  // Generate P-256
  await wrapper.get('form').trigger('submit.prevent')

  expect(generateSpy).toHaveBeenCalledWith('proj-123', expect.objectContaining({
    provider: 'openssl',
    algorithm: 'EC',
    curve: 'secp256r1'
  }))

  // Select P-384
  await wrapper.get('select[aria-label="算法选择"]').setValue('P-384')
  await wrapper.get('form').trigger('submit.prevent')

  expect(generateSpy).toHaveBeenCalledWith('proj-123', expect.objectContaining({
    provider: 'openssl',
    algorithm: 'EC',
    curve: 'secp384r1'
  }))

  generateSpy.mockRestore()
  capsSpy.mockRestore()
 })

 it('ParameterField fills public key reference when target parameter requires PUBLIC_KEY', async () => {
  const capsSpy = vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
    providers: [{ id: 'gmssl', available: true, version: '3.3', algorithms: ['SM2'] }],
    algorithms: [{ id: 'SM2', kind: 'PRIVATE_KEY', bits: [], curves: ['sm2'], providers: ['gmssl'] }]
  })
  const generateSpy = vi.spyOn(api, 'generateKey').mockResolvedValue({
    provider: 'gmssl',
    algorithm: 'SM2',
    storage: 'MANAGED',
    reference: 'key:priv-123',
    key: { id: 'priv-123', name: 'SM2-Priv', algorithm: 'SM2', keyKind: 'PRIVATE_KEY', encoding: 'PEM', validationStatus: 'VALIDATED', createdAt: '', updatedAt: '', stateful: false, hasManagedPassphrase: true, projectId: 'p' },
    publicKey: { id: 'pub-456', name: 'SM2-Pub', algorithm: 'SM2', keyKind: 'PUBLIC_KEY', encoding: 'PEM', validationStatus: 'VALIDATED', createdAt: '', updatedAt: '', stateful: false, hasManagedPassphrase: false, projectId: 'p' },
    warnings: []
  })

  const pubParam = parameter({ name: 'pubkey', type: 'INPUT_FILE', allowedKeyKinds: ['PUBLIC_KEY'] })
  const wrapper = mount(ParameterField, {
    props: {
      parameter: pubParam,
      toolId: 'sm2verify',
      projectId: 'p',
      modelValue: '',
      keys: [],
      files: []
    }
  })

  // Open dialog and generate
  const btn = wrapper.find('.gen-ssl-btn')
  expect(btn.exists()).toBe(true)
  await btn.trigger('click')

  const dialog = wrapper.findComponent(KeyGenerateDialog)
  expect(dialog.exists()).toBe(true)
  await flushPromises()

  await dialog.get('form').trigger('submit.prevent')
  await flushPromises()

  // update:modelValue must emit key:pub-456, NOT key:priv-123!
  expect(wrapper.emitted('update:modelValue')?.[0]).toEqual(['key:pub-456'])

  generateSpy.mockRestore()
  capsSpy.mockRestore()
 })

 it('ParameterField shows dedicated tool navigation button for SM9 and PQC tools without generic keygen', () => {
  const sm9Param = parameter({ name: 'in', type: 'INPUT_FILE', allowedKeyKinds: ['MASTER_KEY'] })
  const wrapper = mount(ParameterField, {
    props: {
      parameter: sm9Param,
      toolId: 'sm9keygen',
      projectId: 'p',
      modelValue: '',
      keys: [],
      files: []
    }
  })

  expect(wrapper.text()).toContain('生成 SM9 主密钥 (sm9setup) ↗')
  expect(wrapper.find('.gen-ssl-btn').text()).toContain('sm9setup')
  expect(wrapper.findComponent(KeyGenerateDialog).exists()).toBe(false)
 })
})


describe('keygen review boundary matrix', () => {
  afterEach(() => vi.restoreAllMocks())
  it('filters unavailable providers as well as algorithm provider membership', async () => {
    vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
      providers: [
        { id: 'gmssl', available: false, algorithms: ['SM4', 'EC'] },
        { id: 'openssl', available: true, algorithms: ['EC'] }
      ],
      algorithms: [
        { id: 'SM4', kind: 'SYMMETRIC_KEY', bits: [128], providers: ['gmssl'] },
        { id: 'EC', kind: 'PRIVATE_KEY', curves: ['secp256r1'], providers: ['openssl'] }
      ]
    })
    const wrapper = mount(KeyGenerateDialog, { props: { visible: true, projectId: 'p' } })
    await flushPromises()
    expect(wrapper.get('input[value=gmssl]').attributes('disabled')).toBeDefined()
    expect(wrapper.findAll('select[aria-label="算法选择"] option').map(o => o.attributes('value'))).toEqual(['P-256'])
    vi.mocked(api.getKeyGenCapabilities).mockResolvedValueOnce({ providers: [{ id: 'gmssl', available: false, algorithms: ['SM4'] }], algorithms: [{ id: 'SM4', kind: 'SYMMETRIC_KEY', bits: [128], providers: ['gmssl'] }] })
    const unavailable = mount(KeyGenerateDialog, { props: { visible: true, projectId: 'p' } })
    await flushPromises()
    expect(unavailable.get('button[type=submit]').attributes('disabled')).toBeDefined()
    unavailable.unmount()
    wrapper.unmount()
  })
  it.each([
    ['sm2sign', 'key', 'PRIVATE_KEY', ['SM2']],
    ['sm2verify', 'pubkey', 'PUBLIC_KEY', ['SM2']],
    ['sm9keygen', 'in', 'MASTER_KEY', []],
    ['sm9sign', 'key', 'PRIVATE_KEY', []],
    ['lmssign', 'key', 'STATEFUL_PRIVATE_KEY', []],
    ['lmsverify', 'pubkey', 'PUBLIC_KEY', []],
    ['sphincssign', 'key', 'PRIVATE_KEY', []],
    ['kyberencap', 'pubkey', 'PUBLIC_KEY', []],
    ['dilithiumsign', 'key', 'PRIVATE_KEY', []],
    ['falconsign', 'key', 'PRIVATE_KEY', []],
    ['eckeygen', 'key', 'PRIVATE_KEY', ['P-256', 'P-384']]
  ])('offers only matching quick algorithms for %s/%s', async (toolId, name, keyKind, expected) => {
    vi.spyOn(api, 'getKeyGenCapabilities').mockResolvedValue({
      providers: [{ id: 'gmssl', available: true, algorithms: ['SM2', 'EC'] }],
      algorithms: [
        { id: 'SM2', kind: 'PRIVATE_KEY', curves: ['sm2p256v1'], providers: ['gmssl'] },
        { id: 'EC', kind: 'PRIVATE_KEY', curves: ['secp256r1', 'secp384r1'], providers: ['gmssl'] }
      ]
    })
    const wrapper = mount(KeyGenerateDialog, { props: { visible: true, projectId: 'p', toolId: String(toolId), targetParameter: parameter({ name: String(name), type: 'INPUT_FILE', allowedKeyKinds: [String(keyKind)] }) } })
    await flushPromises()
    const options = wrapper.findAll('select[aria-label="算法选择"] option').filter(o => !(o.element as HTMLOptionElement).disabled).map(o => o.attributes('value'))
    expect(options).toEqual(expected)
    wrapper.unmount()
  })
  it('fills temporary public FILE and never falls back to a private FILE', async () => {
    const wrapper = mount(ParameterField, { props: { parameter: parameter({ name: 'pubkey', type: 'INPUT_FILE', allowedKeyKinds: ['PUBLIC_KEY'] }), toolId: 'sm2verify', projectId: 'p', modelValue: '', keys: [], files: [] } })
    const dialog = wrapper.getComponent(KeyGenerateDialog)
    const file = { id: 'public-file', name: 'pub.pem', size: 100, mediaType: 'application/x-pem-file', createdAt: '', temporary: true }
    dialog.vm.$emit('generated', { provider: 'gmssl', algorithm: 'SM2', storage: 'TEMPORARY', reference: 'file:private-file', temporaryFile: { ...file, id: 'private-file' }, temporaryPublicKeyFile: file, warnings: [] })
    await flushPromises()
    expect(wrapper.emitted('update:modelValue')).toEqual([['file:public-file']])
    dialog.vm.$emit('generated', { provider: 'gmssl', algorithm: 'SM2', storage: 'TEMPORARY', reference: 'file:private-file', temporaryFile: { ...file, id: 'private-file' }, warnings: [] })
    await flushPromises()
    expect(wrapper.emitted('update:modelValue')).toHaveLength(1)
    expect(wrapper.text()).toContain('生成响应缺少公钥材料')
    wrapper.unmount()
  })
  it('does not offer key generation on SM9 plaintext input', () => {
    const wrapper = mount(ParameterField, { props: { parameter: parameter({ name: 'in', type: 'INPUT_FILE' }), toolId: 'sm9sign', projectId: 'p', modelValue: '', keys: [], files: [] } })
    expect(wrapper.find('.gen-ssl-btn').exists()).toBe(false)
    expect(wrapper.findComponent(KeyGenerateDialog).exists()).toBe(false)
    wrapper.unmount()
  })
})
