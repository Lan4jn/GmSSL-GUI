import { describe, it, expect, vi, afterEach } from 'vitest'
import { flushPromises, mount } from '@vue/test-utils'
import App from '../src/App.vue'
import { tool } from './fixtures'
import type { CertificateTreeResponse } from '../src/types'
const project={id:'12345678-1234-1234-1234-123456789abc',name:'真实项目',role:'VIEWER',createdAt:'2026-01-01T00:00:00Z'}
const catalog={provider:'gmssl',version:'test-build',sourceCommit:'abc',categories:['digest'],coverage:{tested:1},tools:[tool({id:'sm3',title:'SM3 摘要',command:'sm3',sensitiveOutput:true})]}
const mounted: ReturnType<typeof mount>[]=[]
afterEach(()=>{mounted.forEach(w=>w.unmount());mounted.length=0;vi.unstubAllGlobals();vi.restoreAllMocks()})
function setup(extra:Record<string,unknown>={}){
 const responses:Record<string,unknown>={'/auth/me':{user:{id:'u',username:'reader',role:'USER'},csrfToken:'csrf'},'/projects':[project],'/capabilities':catalog,[`/projects/${project.id}/keys`]:[],[`/projects/${project.id}/files`]:[],[`/projects/${project.id}/jobs`]:[],...extra}
 vi.stubGlobal('fetch',vi.fn(async(path:string)=>new Response(JSON.stringify(responses[path.replace('/api/v1','')]??[]))))
 const wrapper=mount(App);mounted.push(wrapper);return wrapper
}
describe('API-backed workspace views',()=>{
 it('shows real empty statistics in advanced mode and hides admin/owner navigation for viewer',async()=>{
  const wrapper=setup();await flushPromises();expect(wrapper.text()).toContain('真实项目');
  // Click 高级模式 to view traditional statistics and advanced dashboard
  await wrapper.findAll('.mode-switcher button').find(b=>b.text().includes('高级模式'))!.trigger('click');
  expect(wrapper.findAll('.stat-card>strong').map(n=>n.text())).toEqual(['0','0','0','1']);const nav=wrapper.get('nav').text();expect(nav).not.toContain('审计日志');expect(nav).not.toContain('用户管理');expect(wrapper.text()).toContain('还没有执行任务')
 })
 it('renders catalog-driven tool metadata without fake success',async()=>{
  const wrapper=setup();await flushPromises();
  await wrapper.findAll('.mode-switcher button').find(b=>b.text().includes('高级模式'))!.trigger('click');
  await wrapper.findAll('nav button').find(n=>n.text().includes('算法工具'))!.trigger('click');expect(wrapper.findAll('.tool-card')).toHaveLength(1);expect(wrapper.get('.tool-card').text()).toContain('未验证');await wrapper.get('.tool-card').trigger('click');expect(wrapper.text()).toContain('当前项目权限只支持查看');expect(wrapper.get('fieldset').attributes('disabled')).toBeDefined()
 })
 it('never previews sensitive stdout and escapes diagnostic HTML',async()=>{
  const job={id:'job1',projectId:project.id,toolId:'sm3',status:'SUCCEEDED',createdAt:'2026-01-01T00:00:00Z',truncated:false,artifacts:[],stdoutPreview:'PRIVATE KEY DO NOT SHOW',stderrPreview:'<img src=x onerror=alert(1)>'}
  const wrapper=setup({[`/projects/${project.id}/jobs`]:[job],[`/projects/${project.id}/jobs/job1`]:job});await flushPromises();await wrapper.findAll('nav button').find(n=>n.text().includes('任务历史'))!.trigger('click');await wrapper.get('.job-list .recent-job').trigger('click');await flushPromises();expect(wrapper.text()).not.toContain('PRIVATE KEY DO NOT SHOW');expect(wrapper.text()).toContain('<img src=x onerror=alert(1)>');expect(wrapper.find('img').exists()).toBe(false)
 })
 it('does not invent zeros when project data has not loaded',async()=>{
  const fetch=vi.fn(async(path:string)=>{const p=path.replace('/api/v1','');if(p==='/auth/me')return new Response(JSON.stringify({user:{id:'u',username:'reader',role:'USER'},csrfToken:'csrf'}));if(p==='/projects')return new Response(JSON.stringify([project]));if(p==='/capabilities')return new Response(JSON.stringify(catalog));return new Response(JSON.stringify({code:'UPSTREAM',message:'实际读取错误',requestId:'req-1'}),{status:503})});vi.stubGlobal('fetch',fetch);const wrapper=mount(App);mounted.push(wrapper);await flushPromises();expect(wrapper.text()).toContain('实际读取错误');
  // Click 高级模式 to inspect stats cards
  await wrapper.findAll('.mode-switcher button').find(b=>b.text().includes('高级模式'))!.trigger('click');
  expect(wrapper.findAll('.stat-card>strong').map(n=>n.text())).toEqual(['—','—','—','1'])
 })
 it('renders temporary file badge and respects artifact download and promote controls',async()=>{
  const editorProject={...project,role:'EDITOR'}
  const tempFile={id:'f1',name:'temp_input.bin',size:1024,mediaType:'application/octet-stream',createdAt:'2026-01-01T00:00:00Z',temporary:true}
  const lmsTool=tool({id:'lmskeygen',title:'LMS 密钥生成',command:'lmskeygen',sensitiveOutput:false})
  const catalogWithLms={...catalog,tools:[...catalog.tools,lmsTool]}
  const job={id:'job-lms',projectId:project.id,toolId:'lmskeygen',status:'SUCCEEDED',createdAt:'2026-01-01T00:00:00Z',truncated:false,artifacts:[
   {id:'art-pri',name:'lms.pri',size:64,mediaType:'application/octet-stream',sensitive:true,statefulPrivate:true,promotable:true,downloadable:false},
   {id:'art-pub',name:'lms.pub',size:32,mediaType:'application/octet-stream',sensitive:false,statefulPrivate:false,promotable:false,downloadable:true}
  ]}
  const wrapper=setup({
   '/projects':[editorProject],
   '/capabilities':catalogWithLms,
   [`/projects/${project.id}/files`]:[tempFile],
   [`/projects/${project.id}/jobs`]:[job],
   [`/projects/${project.id}/jobs/job-lms`]:job
  })
  await flushPromises()
  await wrapper.findAll('nav button').find(n=>n.text().includes('密钥库'))!.trigger('click')
  await flushPromises()
  const allTabBtn = wrapper.findAll('.materials-header-tabs button').find(b=>b.text().includes('全部材料与密钥'))
  if (allTabBtn) await allTabBtn.trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('temp_input.bin')
  expect(wrapper.text()).toContain('任务临时')
  await wrapper.findAll('nav button').find(n=>n.text().includes('任务历史'))!.trigger('click')
  await wrapper.get('.job-list .recent-job').trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('单一权威私钥')
  expect(wrapper.text()).toContain('受控晋升')
  const downloadButtons=wrapper.findAll('.artifact .icon-button')
  expect(downloadButtons[0].attributes('disabled')).toBeDefined()
  expect(downloadButtons[0].attributes('title')).toContain('状态型私钥禁止原始下载')
  expect(downloadButtons[1].attributes('disabled')).toBeUndefined()
 })
 it('supports vault key generation dialog and managed passphrase reveal',async()=>{
  const editorProject={...project,role:'EDITOR'}
  const managedKey={
    id:'key-managed-1',
    projectId:project.id,
    name:'SM2-Vault-Key',
    algorithm:'SM2',
    keyKind:'PRIVATE_KEY',
    encoding:'PEM',
    validationStatus:'VALIDATED',
    createdAt:'2026-01-01T00:00:00Z',
    updatedAt:'2026-01-01T00:00:00Z',
    stateful:false,
    hasManagedPassphrase:true,
    generationProvider:'gmssl'
  }
  const wrapper=setup({
    '/projects':[editorProject],
    [`/projects/${project.id}/keys`]:[managedKey],
    [`/projects/${project.id}/keys/${managedKey.id}/reveal-passphrase`]:{passphrase:'SafePass-1234'}
  })
  await flushPromises()

  // Navigate to keys page and switch to raw materials/keys view
  await wrapper.findAll('nav button').find(n=>n.text().includes('密钥库'))!.trigger('click')
  await flushPromises()
  const allTab = wrapper.findAll('.materials-header-tabs button').find(b=>b.text().includes('全部材料与密钥'))
  if (allTab) { await allTab.trigger('click'); await flushPromises() }

  // Key should show managed passphrase badge
  expect(wrapper.text()).toContain('SM2-Vault-Key')
  expect(wrapper.text()).toContain('已托管口令')

  // Generate SSL key button should exist for editor
  const genBtn=wrapper.findAll('button').find(b=>b.text().includes('生成密钥 (SSL)'))
  expect(genBtn).toBeDefined()
  await genBtn!.trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('生成加密密钥材料')

  // Reveal passphrase test
  const revealBtn=wrapper.findAll('button').find(b=>b.text()==='查看口令')
  expect(revealBtn).toBeDefined()
  await revealBtn!.trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('口令: SafePass-1234')
 })
 it('displays certificate wizard entry banner on certificate page and toggles wizard',async()=>{
  const certTool=tool({id:'certgen',category:'certificate',title:'证书生成',command:'certgen'})
  const catalogWithCert={...catalog,categories:['digest','certificate'],tools:[...catalog.tools,certTool]}
  const wrapper=setup({
    '/capabilities':catalogWithCert
  })
  await flushPromises()

  // Switch to advanced mode and navigate to certificate page
  await wrapper.findAll('.mode-switcher button').find(b=>b.text().includes('高级模式'))!.trigger('click')
  await wrapper.findAll('nav button').find(n=>n.text().includes('证书工具'))!.trigger('click')
  await flushPromises()

  // Entry banner should be present
  expect(wrapper.text()).toContain('证书快捷向导')
  expect(wrapper.text()).toContain('覆盖自签名、根CA/中间CA、CSR申请、CA签发以及 TLCP 国密双证书全流程向导')

  const openWizardBtn=wrapper.findAll('button').find(b=>b.text().includes('打开证书快捷向导'))
  expect(openWizardBtn).toBeDefined()
  await openWizardBtn!.trigger('click')
  await flushPromises()

  expect(wrapper.text()).toContain('国密与安全证书向导')
  expect(wrapper.text()).toContain('收起证书向导')

  // Toggle off
  await wrapper.findAll('button').find(b=>b.text()==='关闭向导')!.trigger('click')
  await flushPromises()
  expect(wrapper.text()).not.toContain('国密与安全证书向导')
 })
})


describe('revealed credential lifecycle', () => {
 const key = { id: 'key-credential', projectId: project.id, name: 'Managed SM2', algorithm: 'SM2', keyKind: 'PRIVATE_KEY', encoding: 'PEM', validationStatus: 'VALIDATED', createdAt: '', updatedAt: '', stateful: false, hasManagedPassphrase: true }
 it.each(['page', 'dialog', 'project'])('clears displayed passphrase on %s change', async context => {
  const other = { ...project, id: 'other-project', name: '另一个项目', role: 'OWNER' }
  const wrapper = setup({ '/projects': [{ ...project, role: 'OWNER' }, other], ['/projects/'+project.id+'/keys']: [key], ['/projects/'+project.id+'/keys/'+key.id+'/reveal-passphrase']: { passphrase: 'ephemeral-only-passphrase' } })
  await flushPromises()
  const keysNav = async () => {
   await wrapper.findAll('nav button').find(b => b.text().includes('密钥库'))!.trigger('click')
   await flushPromises()
   const allTab = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('全部材料与密钥'))
   if (allTab) { await allTab.trigger('click'); await flushPromises() }
  }
  await keysNav()
  await wrapper.get('button[title="查看平台加密保存的私钥口令"]').trigger('click')
  await flushPromises()
  expect(wrapper.text()).toContain('ephemeral-only-passphrase')
  if(context === 'page') {
   await wrapper.findAll('nav button').find(b=>b.text().includes('任务历史'))!.trigger('click')
   await keysNav()
  } else if(context === 'dialog') {
   await wrapper.get('button[aria-label="导出密钥"]').trigger('click')
   await wrapper.get('.modal button[aria-label="关闭对话框"]').trigger('click')
  } else {
   await wrapper.get('#project-switch').setValue(other.id)
   await flushPromises()
   await wrapper.get('#project-switch').setValue(project.id)
   await flushPromises()
   await keysNav()
  }
  expect(wrapper.text()).not.toContain('ephemeral-only-passphrase')
 })
 it('discards a delayed reveal response after leaving its context', async () => {
  const wrapper = setup({ '/projects': [{ ...project, role: 'OWNER' }], ['/projects/'+project.id+'/keys']: [key] })
  await flushPromises()
  const original = globalThis.fetch
  let resolveReveal!: (r: Response) => void
  vi.stubGlobal('fetch', vi.fn((path: string, init?: RequestInit) => path.endsWith('/reveal-passphrase') ? new Promise<Response>(r=>{resolveReveal=r}) : original(path,init)))
  await wrapper.findAll('nav button').find(b=>b.text().includes('密钥库'))!.trigger('click')
  await flushPromises()
  const allTab = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('全部材料与密钥'))
  if (allTab) { await allTab.trigger('click'); await flushPromises() }
  await wrapper.get('button[title="查看平台加密保存的私钥口令"]').trigger('click')
  await wrapper.findAll('nav button').find(b=>b.text().includes('任务历史'))!.trigger('click')
  resolveReveal(new Response(JSON.stringify({ passphrase: 'late-secret' })))
  await flushPromises()
  await wrapper.findAll('nav button').find(b=>b.text().includes('密钥库'))!.trigger('click')
  await flushPromises()
  const allTab2 = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('全部材料与密钥'))
  if (allTab2) { await allTab2.trigger('click'); await flushPromises() }
  expect(wrapper.text()).not.toContain('late-secret')
 })

  it('supports switching to 证书库 (按 CA 分组) sub-tab in keys page and renders CertificateTree', async () => {
    const certTreeData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:112233',
          name: 'app_root_ca.pem',
          category: 'ROOT_CA',
          subjectCN: 'App Test Root CA',
          issuerCN: 'App Test Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: [],
          downloadRef: 'file:f-root'
        }
      ],
      csrs: [],
      bundles: []
    }

    const wrapper = setup({
      '/projects': [{ ...project, role: 'OWNER' }],
      ['/projects/' + project.id + '/certificates']: certTreeData
    })
    await flushPromises()

    // Navigate to keys page
    await wrapper.findAll('nav button').find(b => b.text().includes('密钥库'))!.trigger('click')
    await flushPromises()

    // By default keysSubTab is 'tree', CertificateTree is rendered directly
    expect(wrapper.text()).toContain('App Test Root CA')
    expect(wrapper.text()).toContain('根 CA')

    // Switch to 全部材料与密钥
    const allTabBtn = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('全部材料与密钥'))!
    await allTabBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('托管材料由服务端 AES-256-GCM 加密')
  })

  it('filters navigation in simple mode and restores full navigation in advanced mode', async () => {
    const adminUser = { id: 'u-admin', username: 'admin', role: 'ADMIN' }
    const wrapper = setup({
      '/auth/me': { user: adminUser, csrfToken: 'csrf' },
      '/projects': [{ ...project, role: 'OWNER' }]
    })
    await flushPromises()

    // In default simple mode, non-certificate tools, protocol, and low-frequency admin are hidden
    const simpleNavTexts = wrapper.findAll('nav button').map(b => b.text())
    expect(simpleNavTexts).toContain('工作台')
    expect(simpleNavTexts).toContain('密钥库')
    expect(simpleNavTexts).toContain('任务历史')
    expect(simpleNavTexts).toContain('项目与成员')
    expect(simpleNavTexts).not.toContain('算法工具')
    expect(simpleNavTexts).not.toContain('证书工具')
    expect(simpleNavTexts).not.toContain('协议任务')
    expect(simpleNavTexts).not.toContain('用户管理')
    expect(simpleNavTexts).not.toContain('审计日志')

    // Switch to advanced mode
    const advModeBtn = wrapper.findAll('.mode-switcher button').find(b => b.text().includes('高级模式'))!
    await advModeBtn.trigger('click')
    await flushPromises()

    // Full navigation is restored in advanced mode
    const advNavTexts = wrapper.findAll('nav button').map(b => b.text())
    expect(advNavTexts).toContain('算法工具')
    expect(advNavTexts).toContain('证书工具')
    expect(advNavTexts).toContain('协议任务')
    expect(advNavTexts).toContain('用户管理')
    expect(advNavTexts).toContain('审计日志')

    // When on an advanced page (e.g. 算法工具), switching to simple mode falls back to dashboard
    await wrapper.findAll('nav button').find(b => b.text().includes('算法工具'))!.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('算法与能力目录')

    const simpleModeBtn = wrapper.findAll('.mode-switcher button').find(b => b.text().includes('简单模式'))!
    await simpleModeBtn.trigger('click')
    await flushPromises()

    // Page falls back to dashboard
    expect(wrapper.find('.simple-workbench').exists()).toBe(true)
  })

  it('resets keysSubTab to tree when switching project', async () => {
    const otherProject = { ...project, id: 'proj-other', name: '第二项目' }
    const wrapper = setup({
      '/projects': [{ ...project, role: 'OWNER' }, otherProject]
    })
    await flushPromises()

    await wrapper.findAll('nav button').find(b => b.text().includes('密钥库'))!.trigger('click')
    await flushPromises()

    // Manually switch to all
    const allTabBtn = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('全部材料与密钥'))!
    await allTabBtn.trigger('click')
    await flushPromises()
    expect(wrapper.text()).toContain('托管材料由服务端 AES-256-GCM 加密')

    // Switch project
    await wrapper.get('#project-switch').setValue(otherProject.id)
    await flushPromises()

    // keysSubTab is reset to 'tree'
    const treeTabBtn = wrapper.findAll('.materials-header-tabs button').find(b => b.text().includes('证书库 (按 CA 分组)'))!
    expect(treeTabBtn.classes()).toContain('active')
  })
})
