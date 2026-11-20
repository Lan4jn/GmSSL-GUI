<script setup lang="ts">
import { computed, ref, watch, defineAsyncComponent } from 'vue'
import { Activity, ArrowUpRight, Boxes, Check, ChevronRight, CircleHelp, Cpu, Download, FileKey2, FileText, FlaskConical, FolderKanban, Gauge, Globe2, KeyRound, LockKeyhole, LogOut, Menu, Plus, RefreshCw, Search, ShieldCheck, Shield, Trash2, Users, X } from 'lucide-vue-next'
import { useWorkspace } from './workspace'
import { post, request, errorMessage, download, revealKeyPassphrase } from './api'
import { canRun } from './forms'
import { canDownloadArtifact, canPromoteArtifact } from './artifacts'
import type { Tool, Key, Artifact, User, GenerateKeyResponse } from './types'
import { categoryNames, statusNames } from './types'
import ToolForm from './components/ToolForm.vue'
import KeyGenerateDialog from './components/KeyGenerateDialog.vue'
import SimpleWorkbench from './components/SimpleWorkbench.vue'
import CertificateTree from './components/CertificateTree.vue'
import StandardCertManager from './components/StandardCertManager.vue'
const w=useWorkspace()
const {user,booting,busy,loading,error,success,projects,projectId,project,catalog,catalogError,dataError,keys,files,jobs,members,users,audit,ready,page,selectedJob,mobileNav,manager,editor,prefix}=w
const username=ref(''),password=ref(''),query=ref(''),category=ref('all'),selectedToolId=ref(''),jobFilter=ref('all'),toolForm=ref<InstanceType<typeof ToolForm>>()
const workbenchMode = ref<'simple' | 'advanced'>('simple')
const keysSubTab = ref<'all' | 'tree'>('tree')
const navigation=[{id:'dashboard',title:'工作台',icon:Gauge},{id:'tools',title:'算法工具',icon:Boxes},{id:'keys',title:'密钥库',icon:KeyRound},{id:'certificates',title:'证书工具',icon:FileKey2},{id:'standard-certs',title:'客户端证书',icon:ShieldCheck},{id:'protocol',title:'协议任务',icon:Globe2},{id:'jobs',title:'任务历史',icon:Activity},{id:'projects',title:'项目与成员',icon:FolderKanban},{id:'audit',title:'审计日志',icon:ShieldCheck},{id:'users',title:'用户管理',icon:Users}]
const visibleNav=computed(()=>navigation.filter(n=>{
  if (workbenchMode.value === 'simple' && ['tools', 'certificates', 'standard-certs', 'protocol', 'audit', 'users'].includes(n.id)) return false
  if (n.id==='users'||n.id==='standard-certs') return user.value?.role==='ADMIN'
  if (n.id==='audit') return manager.value
  return true
}))
watch(workbenchMode, (mode) => {
  if (mode === 'simple' && ['tools', 'certificates', 'standard-certs', 'protocol', 'audit', 'users'].includes(page.value)) {
    page.value = 'dashboard'
  }
})
const title=computed(()=>navigation.find(n=>n.id===page.value)?.title??'工作台')
const availableTools=computed(()=>catalog.value?.tools.filter(t=>page.value==='certificates'?t.category==='certificate':page.value==='protocol'?t.category==='protocol':true)??[])
const toolCategories=computed(()=>[...new Set(availableTools.value.map(t=>t.category))])
const filteredTools=computed(()=>availableTools.value.filter(t=>(category.value==='all'||t.category===category.value)&&`${t.title} ${t.command} ${t.description}`.toLowerCase().includes(query.value.toLowerCase())))
const selectedTool=computed(()=>catalog.value?.tools.find(t=>t.id===selectedToolId.value))
const activeJobs=computed(()=>jobs.value.filter(j=>['RUNNING','QUEUED'].includes(j.status)))
const filteredJobs=computed(()=>jobs.value.filter(j=>jobFilter.value==='all'||j.status===jobFilter.value))
const toolsPage=computed(()=>['tools','certificates','protocol'].includes(page.value))
watch(page,()=>{query.value='';category.value='all';selectedToolId.value='';mobileNav.value=false;clearRevealedPassphrases()})
watch(projectId,()=>{selectedToolId.value='';modal.value=null;revealedPassphrases.value={};keysSubTab.value='tree'})
const date=(v?:string)=>v?new Date(v).toLocaleString('zh-CN',{hour12:false}):'—'
const bytes=(v:number)=>v<1024?`${v} B`:v<1024*1024?`${(v/1024).toFixed(1)} KiB`:`${(v/1024/1024).toFixed(1)} MiB`
const toolTitle=(id:string)=>catalog.value?.tools.find(t=>t.id===id)?.title??id
const badge=(s:string)=>['SUCCEEDED','tested','VALIDATED'].includes(s)?'good':['FAILED','TIMED_OUT','unavailable'].includes(s)?'bad':['QUEUED','RUNNING'].includes(s)?'live':'neutral'
const evidence=(v:unknown)=>typeof v==='string'?v:JSON.stringify(v,null,2)
function openTool(tool:Tool){selectedToolId.value=tool.id}
async function login(){const secret=password.value;password.value='';await w.login(username.value,secret)}
async function uploadParameter(payload:{file:File;parameter?:string;index?:number;temporary?:boolean;isStdin?:boolean}){await w.act(async()=>{const temporary=payload.temporary??true;const f=await w.upload(payload.file,temporary);if(payload.isStdin){toolForm.value?.setUploadedStdin(`file:${f.id}`)}else if(payload.parameter){toolForm.value?.setUploadedReference(payload.parameter,`file:${f.id}`,payload.index)}success.value=`输入文件已加密保存至项目${temporary?'（任务结束自动清理）':''}`})}
type Modal = {kind:'project'|'import'|'save'|'export'|'delete'|'member'|'user'|'editUser'|'fileDelete';title:string;key?:Key;artifact?:Artifact;user?:User;fileId?:string;fileName?:string}
const modal=ref<Modal|null>(null),form=ref<Record<string,string>>({}),selectedFile=ref<File|null>(null),modalError=ref('')
watch(()=>modal.value,m=>{revealedPassphrases.value={};if(!m){form.value={};selectedFile.value=null;modalError.value=''}})
const kinds=['PRIVATE_KEY','PUBLIC_KEY','SYMMETRIC_KEY','MASTER_KEY']
const jobTool = computed(()=>catalog.value?.tools.find(t=>t.id===selectedJob.value?.toolId))
const controlledKeygen = computed(()=>['lmskeygen','hsskeygen','xmsskeygen','xmssmtkeygen'].includes(catalog.value?.tools.find(t=>t.id===selectedJob.value?.toolId)?.command??''))
function openModal(m:Modal){form.value={name:'',description:'',algorithm:'',keyKind:'PRIVATE_KEY',encoding:'RAW',usage:'',role:m.kind==='member'?'EDITOR':'USER',userId:'',username:'',password:'',enabled:'true'};selectedFile.value=null;modalError.value='';modal.value=m;if(m.artifact?.statefulPrivate)form.value.keyKind='STATEFUL_PRIVATE_KEY';if(m.user){form.value.role=m.user.role;form.value.enabled=String(m.user.enabled??true)}}
function chooseFile(event:Event){selectedFile.value=(event.target as HTMLInputElement).files?.[0]??null}
async function submitModal(){const m=modal.value;if(!m)return;modalError.value='';await w.act(async()=>{try{
  const f=form.value,base=prefix.value
  if(m.kind==='project'){await w.createProject(f.name,f.description)}
  if(m.kind==='import'){if(!selectedFile.value)throw new Error('请选择密钥材料文件');if(selectedFile.value.size>16*1024*1024)throw new Error('单个文件最大 16 MiB');const data=new FormData();data.append('file',selectedFile.value);for(const name of ['name','algorithm','keyKind','encoding','usage','description'])if(f[name])data.append(name,f[name]);await request(`${base}/keys`,{method:'POST',body:data});await w.loadProject();success.value='密钥材料已导入并加密托管，验证状态以服务端为准'}
  if(m.kind==='save'){if(!m.artifact||!canPromoteArtifact(m.artifact,jobTool.value))throw new Error('此产物不允许晋升');await post(`${base}/jobs/${selectedJob.value?.id}/artifacts/${m.artifact?.id}/save-key`,{name:f.name,algorithm:f.algorithm,keyKind:m.artifact.statefulPrivate?'STATEFUL_PRIVATE_KEY':f.keyKind,encoding:f.encoding,usage:f.usage,description:f.description});await w.loadProject();success.value='产物已存入密钥库'}
  if(m.kind==='export'){await download(`${base}/keys/${m.key?.id}/download`,m.key?.name??'key')}
  if(m.kind==='delete'){await request(`${base}/keys/${m.key?.id}`,{method:'DELETE'});await w.loadProject();success.value='密钥已删除'}
  if(m.kind==='fileDelete'){await request(`${base}/files/${m.fileId}`,{method:'DELETE'});await w.loadProject();success.value='项目文件已删除'}
  if(m.kind==='member'){await request(`${base}/members/${f.userId}`,{method:'PUT',body:JSON.stringify({role:f.role})});await w.loadAdmin();success.value='成员权限已更新'}
  if(m.kind==='user'){await post('/users',{username:f.username,password:f.password,role:f.role});f.password='';await w.loadUsers();success.value='用户已创建'}
  if(m.kind==='editUser'){await request(`/users/${m.user?.id}`,{method:'PATCH',body:JSON.stringify({role:f.role,enabled:f.enabled==='true',...(f.password?{password:f.password}:{})})});f.password='';await w.loadUsers();success.value='用户已更新'}
  modal.value=null;selectedFile.value=null;form.value={}
}catch(e){modalError.value=errorMessage(e);form.value.password='';throw e}})}
async function removeMember(id:string){if(!confirm('确认移除此项目成员？服务端将保护最后一位所有者。'))return;await w.act(async()=>{await request(`${prefix.value}/members/${id}`,{method:'DELETE'});await w.loadAdmin()})}
async function downloadArtifact(a:Artifact){if(!canDownloadArtifact(a,jobTool.value))return;if(a.sensitive&&!confirm(`产物 ${a.name} 含敏感材料，确认下载到本机？`))return;await w.fetchDownload(`${prefix.value}/jobs/${selectedJob.value?.id}/artifacts/${a.id}/download`,a.name)}
async function uploadProjectFile(event:Event){const input=event.target as HTMLInputElement,f=input.files?.[0];if(f)await w.act(async()=>{await w.upload(f,false);success.value='项目文件已上传并加密保存'});input.value=''}

const CertificateWizard = defineAsyncComponent(() => import('./components/CertificateWizard.vue'))
const showKeyGenDialog = ref(false)
const showCertWizard = ref(false)
const revealedPassphrases = ref<Record<string, string>>({})
const revealingKeyId = ref('')
let revealContext = 0
function clearRevealedPassphrases() {
  revealContext++
  revealedPassphrases.value = {}
  revealingKeyId.value = ''
}
watch(user, clearRevealedPassphrases)
watch(selectedToolId, clearRevealedPassphrases)

async function handleRevealPassphrase(key: Key) {
  if (revealedPassphrases.value[key.id]) {
    delete revealedPassphrases.value[key.id]
    return
  }
  const context = revealContext
  const pid = projectId.value
  revealingKeyId.value = key.id
  try {
    const res = await revealKeyPassphrase(pid, key.id)
    if (res.passphrase && context === revealContext && pid === projectId.value) {
      revealedPassphrases.value[key.id] = res.passphrase
    }
  } catch (e) {
    error.value = errorMessage(e)
  } finally {
    if (context === revealContext) revealingKeyId.value = ''
  }
}

async function onKeyGeneratedInVault(res: GenerateKeyResponse) {
  await w.loadProject()
  success.value = `已通过 ${res.provider} 成功生成 ${res.algorithm} 密钥材料并加密托管至密钥库`
}

async function onCertWizardComplete() {
  showCertWizard.value = false
  await w.loadProject()
  success.value = '证书向导已成功签发并保存证书材料'
}

async function onCertWizardNavigateVault() {
  showCertWizard.value = false
  await w.loadProject()
  page.value = 'keys'
  success.value = '已切换至密钥库查看证书与材料'
}

watch(showKeyGenDialog, () => { clearRevealedPassphrases() })
watch(showCertWizard, () => { revealedPassphrases.value = {} })

function handleNavigateTool(toolId: string) {
  const target = catalog.value?.tools.find(t => t.id === toolId)
  if (!target) return
  selectedToolId.value = target.id
  revealedPassphrases.value = {}
}
</script>

<template>
<div v-if="booting" class="boot"><Shield class="brand-symbol"/><p>正在连接密码工作空间…</p></div>
<div v-else-if="!user" class="login-screen">
  <section class="login-story"><div class="brand"><ShieldCheck/><strong>GmSSL<span>密码工作空间</span></strong></div><div class="story-copy"><span class="eyebrow">密码互联 · 协同安全</span><h1>让密码能力，<br>成为团队的日常工具。</h1><p>从一次摘要计算，到密钥的完整生命周期。<br>一个项目工作空间，承载每一次可信操作。</p><div class="story-features"><span><LockKeyhole/> 加密材料托管</span><span><Activity/> 可追溯任务</span><span><Users/> 项目协作</span></div></div><small>GmSSL 软件密码工具箱 · 浏览器工作空间</small></section>
  <section class="login-panel"><div class="login-card"><span class="eyebrow">欢迎登录</span><h2>登录工作空间</h2><p class="muted">使用管理员为你创建的账号继续。</p><form @submit.prevent="login"><div class="field"><label for="username">用户名</label><input id="username" v-model="username" autocomplete="username" required autofocus placeholder="你的账号"></div><div class="field"><label for="password">密码</label><input id="password" v-model="password" type="password" autocomplete="current-password" required placeholder="输入账号密码"></div><p v-if="error" role="alert" class="error-message">{{error}}</p><button class="button primary full" :disabled="busy">{{busy?'正在登录…':'登录工作空间'}} <ArrowUpRight :size="17"/></button></form><div class="login-note"><ShieldCheck :size="18"/> 会话由 HttpOnly Cookie 管理，凭据不保存在浏览器存储中。</div></div></section>
</div>
<div v-else class="app-shell">
  <div v-if="mobileNav" class="sidebar-backdrop" @click="mobileNav=false"/>
  <aside class="sidebar" :class="{open:mobileNav}"><div class="brand"><ShieldCheck/><strong>GmSSL<span>密码工作空间</span></strong></div><div class="project-switch"><label for="project-switch">当前项目</label><select id="project-switch" :disabled="busy||loading" :value="projectId" @change="w.switchProject(($event.target as HTMLSelectElement).value)"><option v-if="projects.length===0" value="">尚无项目</option><option v-for="p in projects" :key="p.id" :value="p.id">{{p.name}}</option></select><span v-if="project" class="project-role">{{project.role}} · 项目工作空间</span></div><span class="nav-heading">工作空间</span><nav><button v-for="item in visibleNav" :key="item.id" :class="{active:page===item.id}" @click="page=item.id"><component :is="item.icon" :size="18"/><span>{{item.title}}</span><span v-if="item.id==='jobs'&&activeJobs.length" class="nav-count">{{activeJobs.length}}</span></button></nav><div class="sidebar-bottom"><div class="engine-meta"><Cpu :size="17"/><div><strong>{{catalog?.provider??'目录未连接'}}</strong><span>{{catalog?.version??'等待能力目录'}}</span></div></div><div class="account"><span class="avatar">{{user.username.slice(0,1).toUpperCase()}}</span><div><strong>{{user.username}}</strong><small>{{user.role==='ADMIN'?'系统管理员':'团队成员'}}</small></div><button class="icon-button" title="退出登录" aria-label="退出登录" :disabled="busy" @click="w.logout"><LogOut :size="17"/></button></div></div></aside>
  <div class="workspace"><header class="topbar"><div class="breadcrumb"><button class="icon-button mobile-menu" aria-label="打开导航" @click="mobileNav=true"><Menu :size="20"/></button><span>{{project?.name??'工作空间'}}</span><ChevronRight :size="14"/><strong>{{title}}</strong></div><div class="topbar-actions">
  <div class="mode-switcher segmented">
    <button type="button" :class="{ active: workbenchMode === 'simple' }" @click="workbenchMode = 'simple'">简单模式</button>
    <button type="button" :class="{ active: workbenchMode === 'advanced' }" @click="workbenchMode = 'advanced'">高级模式</button>
  </div>
  <span class="connection" :class="{offline:catalogError}"><i/> {{catalogError?'目录连接异常':'同源平台会话'}}</span>
  <button class="icon-button" title="刷新服务数据" aria-label="刷新服务数据" :disabled="busy||loading" @click="w.refresh"><RefreshCw :size="17" :class="{spinning:loading}"/></button>
</div></header>
  <main><div class="page-heading"><div><span class="eyebrow">{{toolsPage?'算法与能力目录':page==='keys'?'加密密钥库':page==='jobs'?'任务与执行中心':page==='standard-certs'?'标准客户端证书':'项目与成员协作'}}</span><h1>{{title}}<span class="heading-dot">.</span></h1><p>{{page==='dashboard'?'你的密码工作，从这里开始。所有项目数据均来自平台实时记录。':toolsPage?'探索版本绑定的真实工具能力，配置参数并提交执行任务。':page==='keys'?'管理项目密钥与输入材料。秘密加密托管，不自动预览。':page==='jobs'?'查看真实执行状态、脱敏诊断与任务产物。':page==='standard-certs'?'集中管理与签发客户端证书，严格基于 CSR 签名请求与项目隔离。':'按项目组织协作，让每一次操作都有迹可循。'}}</p></div><button v-if="page==='projects'||!projectId" class="button primary" :disabled="busy" @click="openModal({kind:'project',title:'创建新项目'})"><Plus :size="16"/> 创建项目</button><template v-if="page==='keys'&&editor"><button class="button secondary" style="margin-right:0.5rem" @click="showKeyGenDialog=true"><KeyRound :size="16"/> 生成密钥 (SSL)</button><button class="button primary" @click="openModal({kind:'import',title:'导入密钥材料'})"><Plus :size="16"/> 导入密钥</button></template><button v-if="page==='users'&&user.role==='ADMIN'" class="button primary" @click="openModal({kind:'user',title:'创建用户'})"><Plus :size="16"/> 创建用户</button></div>
  <div v-if="error" role="alert" class="banner error"><CircleHelp :size="18"/><span>{{error}}</span><button class="icon-button" aria-label="关闭错误" @click="error=''">×</button></div><div v-if="success" role="status" class="banner success"><Check :size="18"/><span>{{success}}</span><button class="icon-button" aria-label="关闭提示" @click="success=''">×</button></div><div v-if="catalogError" class="banner warning"><span>能力目录：{{catalogError}}</span><button class="text-button" @click="w.refresh">重试</button></div><div v-if="dataError" class="banner error">项目数据加载失败：{{dataError}}<button class="text-button" @click="w.loadProject()">重试</button></div><div v-if="loading" class="loading-line">正在读取项目数据…</div>
  <template v-if="page==='dashboard'">
  <SimpleWorkbench
    v-if="workbenchMode === 'simple'"
    :project-id="projectId"
    :keys="keys"
    :files="files"
    :disabled="busy||loading"
    @open-keygen="showKeyGenDialog = true"
    @navigate-vault="page = 'keys'"
    @refresh="w.loadProject()"
  />
  <div v-else class="advanced-dashboard"><section class="welcome-panel"><div><span class="pill">密码工具 · 团队协作</span><h2>把复杂的密码操作，<br>交给清晰的工作流。</h2><p>选定项目，选择工具，验证每一个结果。</p><button class="button primary" @click="page='tools'">开始使用工具 <ArrowUpRight :size="17"/></button></div><div class="welcome-art" aria-hidden="true"><div class="orbit orbit-one"/><div class="orbit orbit-two"/><div class="shield-tile"><ShieldCheck :size="65" stroke-width="1.3"/></div><span class="art-chip chip-one"><KeyRound :size="14"/> 项目密钥库</span><span class="art-chip chip-two"><Cpu :size="14"/> GmSSL 执行引擎</span></div></section><div class="stats-grid"><article class="stat-card"><span>项目托管密钥<KeyRound :size="18"/></span><strong>{{ready?keys.length:'—'}}</strong><small>加密保存在项目密钥库</small></article><article class="stat-card"><span>累计任务<Activity :size="18"/></span><strong>{{ready?jobs.length:'—'}}</strong><small>当前项目的真实执行记录</small></article><article class="stat-card"><span>进行中任务<FlaskConical :size="18"/></span><strong>{{ready?activeJobs.length:'—'}}</strong><small>排队中或正在运行</small></article><article class="stat-card"><span>目录工具<Boxes :size="18"/></span><strong>{{catalog?catalog.tools.length:'—'}}</strong><small>已测试 {{catalog?catalog.tools.filter(t=>t.verification.status==='tested').length:'—'}} · 非硬件软件工具</small></article></div><div class="dashboard-columns"><section class="panel"><div class="panel-heading"><h3>最近任务</h3><button class="text-button" @click="page='jobs'">查看全部 <ArrowUpRight :size="14"/></button></div><div v-if="!jobs.length" class="empty"><Activity/><strong>{{ready?'还没有执行任务':'选择项目后查看任务'}}</strong><p>运行一个算法工具，结果将在这里呈现。</p><button class="text-button" @click="page='tools'">探索工具 →</button></div><button v-for="j in jobs.slice(0,5)" :key="j.id" class="recent-job" @click="page='jobs';w.inspectJob(j)"><span class="job-icon"><Cpu :size="17"/></span><div><strong>{{toolTitle(j.toolId)}}</strong><small>{{date(j.createdAt)}}</small></div><span class="badge" :class="badge(j.status)">{{statusNames[j.status]??j.status}}</span></button></section><section class="panel catalog-summary"><div class="panel-heading"><h3>能力与版本</h3><ShieldCheck :size="18"/></div><template v-if="catalog"><p>当前提供方 <strong>{{catalog.provider}}</strong></p><h3 class="version">{{catalog.version}}</h3><code class="commit">{{catalog.sourceCommit}}</code><p class="muted">工具验证状态随目录呈现；已实现与未验证不等同于测试通过。</p><details><summary>查看 API 覆盖与差额</summary><pre>{{JSON.stringify(catalog.coverage,null,2)}}</pre></details></template><div v-else class="empty"><p>尚未取得能力目录</p></div></section></div></div></template>
  <template v-else-if="toolsPage">
<div v-if="page==='certificates'" class="cert-wizard-entry-banner notice" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
  <div>
    <strong>证书快捷向导</strong>
    <p style="margin:0;font-size:0.875rem">覆盖自签名、根CA/中间CA、CSR申请、CA签发以及 TLCP 国密双证书全流程向导</p>
  </div>
  <button type="button" class="button primary small" @click="showCertWizard=!showCertWizard"><FileKey2 :size="16"/> {{ showCertWizard ? '收起证书向导' : '打开证书快捷向导 ↗' }}</button>
</div>
<div v-if="page==='certificates'&&user?.role==='ADMIN'" class="notice" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
  <div>
    <strong>标准客户端证书管理台账</strong>
    <p style="margin:0;font-size:0.875rem">管理员专用：基于 CSR 集中签发标准客户端证书、按指纹查询与吊销管理</p>
  </div>
  <button type="button" class="button secondary small" @click="page='standard-certs'"><ShieldCheck :size="16"/> 打开客户端证书管理 ↗</button>
</div>
<section v-if="page==='certificates'&&showCertWizard" class="panel cert-wizard-panel" style="margin-bottom:1.5rem">
  <div class="panel-heading">
    <h3>国密与安全证书向导</h3>
    <button class="button small secondary" @click="showCertWizard=false">关闭向导</button>
  </div>
  <component :is="CertificateWizard" :project-id="projectId" :keys="keys" :files="files" :disabled="busy||loading" @close="showCertWizard=false" @complete="onCertWizardComplete" @navigate-vault="onCertWizardNavigateVault" />
</section>
<div v-if="!selectedTool" class="catalog-layout"><aside class="category-panel"><h3>工具分类</h3><button :class="{active:category==='all'}" @click="category='all'">全部能力<span>{{availableTools.length}}</span></button><button v-for="c in toolCategories" :key="c" :class="{active:category===c}" @click="category=c">{{categoryNames[c]??c}}<span>{{availableTools.filter(t=>t.category===c).length}}</span></button><div class="category-note"><ShieldCheck :size="18"/> 目录来自实际引擎版本，不包含硬件或 OpenSSL 页面。</div></aside><section class="catalog-content"><div class="search-bar"><Search :size="18"/><input v-model="query" aria-label="搜索工具" placeholder="搜索算法、工具名称或命令…"><span>{{filteredTools.length}} 个工具</span></div><div class="tool-grid"><button v-for="t in filteredTools" :key="t.id" class="tool-card" @click="openTool(t)"><div class="tool-card-top"><span class="tool-icon"><component :is="t.category==='certificate'?FileKey2:t.category==='protocol'?Globe2:Boxes" :size="21"/></span><span class="badge" :class="badge(t.verification.status)">{{statusNames[t.verification.status]??t.verification.status}}</span></div><h3>{{t.title}}</h3><code>{{t.command}}</code><p>{{t.description}}</p><div class="tool-card-bottom"><span>{{categoryNames[t.category]??t.category}}<span v-if="t.adminOnly"> · 管理员</span></span><ArrowUpRight :size="17"/></div></button></div><div v-if="!filteredTools.length" class="empty panel"><Search/><strong>{{catalog?'未找到匹配工具':'等待真实能力目录'}}</strong><p>试试其他搜索词，或刷新平台服务。</p></div></section></div><section v-else class="panel tool-detail"><button class="text-button" @click="selectedToolId=''">← 返回工具目录</button><div class="tool-detail-heading"><div><code>{{selectedTool.command}}</code><h2>{{selectedTool.title}}</h2><p>{{selectedTool.description}}</p></div><span class="badge" :class="badge(selectedTool.verification.status)">{{statusNames[selectedTool.verification.status]??selectedTool.verification.status}}</span></div><div class="tool-meta"><span>{{catalog?.provider}} · {{catalog?.version}}</span><span>{{categoryNames[selectedTool.category]}}</span><span v-if="selectedTool.adminOnly">仅管理员执行</span><span v-if="selectedTool.sensitiveOutput">敏感输出：仅下载，不预览</span></div><details class="verification"><summary>验证证据与限制</summary><pre>{{evidence(selectedTool.verification.evidence)}}</pre></details><div v-if="!projectId" class="notice">请先创建或选择一个项目。</div><div v-else-if="!canRun(user,project,selectedTool)" class="notice">{{selectedTool.verification.status==='unavailable'?'该能力当前不可用，请查看目录证据。':selectedTool.adminOnly&&user.role!=='ADMIN'?'此工具仅系统管理员可执行。':'当前项目权限只支持查看，请联系项目所有者。'}}</div><ToolForm :key="`${projectId}:${selectedTool.id}`" ref="toolForm" :tool="selectedTool" :keys="keys" :files="files" :project-id="projectId" :editor="editor" :disabled="!projectId||!ready||!canRun(user,project,selectedTool)" :busy="busy" @run="w.runJob" @upload="uploadParameter" @refresh-keys="w.loadProject()" @navigate-tool="handleNavigateTool"/></section></template>
  <template v-else-if="page==='keys'">
    <div class="materials-header-tabs" style="display:flex;align-items:center;justify-content:space-between;margin-bottom:1rem">
      <div class="segmented">
        <button type="button" class="tab-btn" :class="{ active: keysSubTab === 'all' }" @click="keysSubTab = 'all'">全部材料与密钥</button>
        <button type="button" class="tab-btn" :class="{ active: keysSubTab === 'tree' }" @click="keysSubTab = 'tree'">证书库 (按 CA 分组)</button>
      </div>
      <div v-if="keysSubTab === 'tree'" class="hint" style="font-size:0.8rem;color:#64748b">
        按根 CA → 中间 CA → 终端证书层级展示信任拓扑树
      </div>
    </div>

    <!-- 证书拓扑树视图 -->
    <CertificateTree v-if="keysSubTab === 'tree'" :project-id="projectId" />

    <!-- 原始全部材料列表视图 -->
    <div v-else class="all-materials-view">
<div class="notice"><LockKeyhole :size="18"/> 托管材料由服务端 AES-256-GCM 加密；导入默认未验证，元数据不是密钥有效性的证明。状态型私钥仅支持受控生成晋升，不开放外部导入或原始导出；pending 故障后应弃用隔离密钥并生成新密钥。</div><section class="panel"><div class="panel-heading"><h3>项目密钥 <span class="count">{{ready?keys.length:'—'}}</span></h3><button class="text-button" @click="page='tools'">使用工具生成密钥 <ArrowUpRight :size="14"/></button></div><div class="table-wrap" v-if="keys.length"><table><thead><tr><th>名称 / 标识</th><th>算法 / 类型</th><th>编码</th><th>托管与口令</th><th>验证状态</th><th>更新时间</th><th>操作</th></tr></thead><tbody><tr v-for="key in keys" :key="key.id"><td><strong>{{key.name}}</strong><small class="mono">{{key.id}}</small><small v-if="key.publicFingerprint">指纹 {{key.publicFingerprint}}</small><small v-if="key.description">{{key.description}}</small></td><td>{{key.algorithm}}<small>{{key.keyKind}}{{key.stateful?' · 状态型':''}}{{key.generationProvider ? ' · ' + key.generationProvider : ''}}</small></td><td><code>{{key.encoding}}</code></td><td><span v-if="key.hasManagedPassphrase" class="badge good">已托管口令</span><span v-else class="badge neutral">未托管口令</span></td><td><span class="badge" :class="badge(key.validationStatus)">{{statusNames[key.validationStatus]??key.validationStatus}}</span></td><td>{{date(key.updatedAt)}}</td><td><div class="actions"><button v-if="key.hasManagedPassphrase&&editor" class="text-button small" :disabled="revealingKeyId===key.id" title="查看平台加密保存的私钥口令" @click="handleRevealPassphrase(key)">{{revealedPassphrases[key.id] ? '口令: ' + revealedPassphrases[key.id] : '查看口令'}}</button><button v-if="!key.stateful&&key.keyKind!=='STATEFUL_PRIVATE_KEY'&&(editor||key.keyKind==='PUBLIC_KEY')" class="icon-button" aria-label="导出密钥" title="导出密钥" @click="openModal({kind:'export',title:'确认导出密钥',key})"><Download :size="17"/></button><button v-if="editor" class="icon-button danger" aria-label="删除密钥" title="删除密钥" @click="openModal({kind:'delete',title:'确认删除密钥',key})"><Trash2 :size="17"/></button></div></td></tr></tbody></table></div><div v-else class="empty"><KeyRound/><strong>项目中尚无密钥</strong><p>导入现有材料，或通过真实工具任务生成并保存。</p></div></section><section class="panel spaced"><div class="panel-heading"><h3>输入材料 <span class="count">{{ready?files.length:'—'}}</span></h3><label v-if="editor" class="button secondary small"><Plus :size="15"/> 上传文件<input class="sr-only" type="file" :disabled="busy" @change="uploadProjectFile"></label></div><div v-for="f in files" :key="f.id" class="file-row"><FileText :size="19"/><div><strong>{{f.name}}<span v-if="f.temporary" class="badge neutral" style="margin-left:6px">任务临时</span></strong><small>{{bytes(f.size)}} · {{f.mediaType}} · {{f.temporary ? '临时文件（任务后自动清理） · ' : ''}}{{date(f.createdAt)}}</small></div><button class="icon-button" title="下载项目文件" aria-label="下载项目文件" @click="w.fetchDownload(`${prefix}/files/${f.id}/download`,f.name)"><Download :size="17"/></button><button v-if="editor" class="icon-button danger" title="删除文件" aria-label="删除文件" @click="openModal({kind:'fileDelete',title:'删除项目输入材料',fileId:f.id,fileName:f.name})"><Trash2 :size="17"/></button></div><p v-if="!files.length" class="table-empty">尚无输入文件。上传后可在工具参数中引用。</p></section></div></template>
  <template v-else-if="page==='jobs'"><div class="jobs-layout"><section class="panel job-list"><div class="panel-heading"><h3>任务记录</h3><select v-model="jobFilter" aria-label="过滤任务状态"><option value="all">全部状态</option><option v-for="s in ['QUEUED','RUNNING','SUCCEEDED','FAILED','TIMED_OUT','CANCELLED']" :key="s" :value="s">{{statusNames[s]}}</option></select></div><button v-for="j in filteredJobs" :key="j.id" class="recent-job" :class="{selected:selectedJob?.id===j.id}" @click="w.inspectJob(j)"><span class="job-icon"><Cpu :size="18"/></span><div><strong>{{toolTitle(j.toolId)}}</strong><small>{{date(j.createdAt)}}</small><small class="mono">{{j.id.slice(0,8)}}</small></div><span class="badge" :class="badge(j.status)">{{statusNames[j.status]??j.status}}</span></button><div v-if="!filteredJobs.length" class="empty"><Activity/><strong>暂无任务记录</strong><p>提交工具任务后，在这里跟踪执行。</p></div></section><section class="panel job-detail"><template v-if="selectedJob"><div class="panel-heading"><h3>{{toolTitle(selectedJob.toolId)}}</h3><span class="badge" :class="badge(selectedJob.status)">{{statusNames[selectedJob.status]??selectedJob.status}}</span></div><dl class="job-facts"><div><dt>任务 ID</dt><dd class="mono">{{selectedJob.id}}</dd></div><div><dt>创建时间</dt><dd>{{date(selectedJob.createdAt)}}</dd></div><div><dt>运行耗时</dt><dd>{{selectedJob.durationMs===undefined||selectedJob.durationMs===null?'—':`${selectedJob.durationMs} ms`}}</dd></div><div><dt>退出码</dt><dd>{{selectedJob.exitCode??'—'}}</dd></div></dl><button v-if="editor&&['QUEUED','RUNNING'].includes(selectedJob.status)" class="button danger-outline" :disabled="busy" @click="w.cancel(selectedJob)">取消任务</button><div v-if="selectedJob.error" class="banner error">{{selectedJob.error}}</div><div v-if="selectedJob.truncated" class="notice">输出已截断，请下载完整产物（若服务端提供）。</div><template v-if="selectedJob.stdoutPreview && catalog?.tools.find(t=>t.id===selectedJob?.toolId)?.sensitiveOutput === false"><h4>标准输出</h4><pre class="output">{{selectedJob.stdoutPreview}}</pre></template><div v-else class="notice">未提供可预览输出。敏感材料仅通过显式下载交付。</div><template v-if="selectedJob.stderrPreview"><h4>执行诊断</h4><pre class="output diagnostic">{{selectedJob.stderrPreview}}</pre></template><div v-if="controlledKeygen" class="notice">状态型 keygen：私钥产物由平台精确识别，禁止原始下载；仅可受控晋升一次，删除后仍不可重复晋升。公钥产物可正常下载。隔离密钥不支持旧备份恢复。</div><h4>任务产物 <span class="count">{{selectedJob.artifacts?.length??0}}</span></h4><div v-for="a in selectedJob.artifacts" :key="a.id" class="artifact"><FileText :size="19"/><div><strong>{{a.name}}</strong><small>{{bytes(a.size)}} · {{a.mediaType}}{{a.sensitive?' · 敏感材料':''}}</small></div><button class="icon-button" :title="!canDownloadArtifact(a,jobTool)?(a.statefulPrivate?'状态型私钥禁止原始下载，仅支持受控晋升':'禁止下载此产物'):'下载产物'" :aria-label="!canDownloadArtifact(a,jobTool)?(a.statefulPrivate?'状态型私钥禁止原始下载，仅支持受控晋升':'禁止下载此产物'):'下载产物'" :disabled="busy||(!editor&&a.sensitive)||!canDownloadArtifact(a,jobTool)" @click="downloadArtifact(a)"><Download :size="17"/></button><button v-if="editor&&selectedJob.status==='SUCCEEDED'&&canPromoteArtifact(a,jobTool)" class="text-button" @click="openModal({kind:'save',title:a.statefulPrivate?'受控晋升状态型私钥':'将任务产物存为密钥',artifact:a})">{{a.statefulPrivate?'受控晋升':'存为密钥'}}</button><span v-if="a.statefulPrivate" class="badge neutral">单一权威私钥</span></div><p v-if="!selectedJob.artifacts?.length" class="muted">此任务暂无可下载产物。</p></template><div v-else class="empty"><FileText/><strong>选择一条任务</strong><p>查看真实状态、诊断与产物。</p></div></section></div></template>
  <template v-else-if="page==='projects'"><section class="panel"><div class="panel-heading"><h3>可访问的项目</h3><span class="muted">{{projects.length}} 个项目</span></div><div v-for="p in projects" :key="p.id" class="project-row"><span class="project-letter">{{p.name.slice(0,1)}}</span><div><strong>{{p.name}}</strong><p>{{p.description||'未设置项目描述'}}</p><small>{{p.role}} · {{date(p.createdAt)}}</small></div><button class="button secondary small" :disabled="projectId===p.id||loading||busy" @click="w.switchProject(p.id)">{{projectId===p.id?'当前项目':'切换项目'}}</button></div><div v-if="!projects.length" class="empty"><FolderKanban/><strong>创建你的第一个项目</strong><p>将任务和密钥材料放在独立的项目边界内。</p></div></section><section v-if="manager&&projectId" class="panel spaced"><div class="panel-heading"><h3>项目成员</h3><button class="button secondary small" @click="openModal({kind:'member',title:'添加或更新项目成员'})"><Plus :size="15"/> 添加成员</button></div><div v-for="m in members" :key="m.userId" class="member-row"><span class="avatar light">{{m.username.slice(0,1).toUpperCase()}}</span><div><strong>{{m.username}}</strong><small class="mono">{{m.userId}}</small></div><span class="badge neutral">{{m.role}}</span><button class="icon-button" title="编辑成员" aria-label="编辑成员" @click="openModal({kind:'member',title:'更新成员权限'});form.userId=m.userId;form.role=m.role"><Users :size="17"/></button><button class="icon-button danger" title="移除成员" aria-label="移除成员" :disabled="busy" @click="removeMember(m.userId)"><Trash2 :size="17"/></button></div></section><div v-else-if="projectId" class="notice spaced">仅项目所有者和系统管理员可管理项目成员。</div></template>
  <section v-else-if="page==='audit'&&manager" class="panel"><div class="panel-heading"><h3>项目审计记录</h3><span class="muted">仅动作与资源标识，不含秘密参数</span></div><div class="table-wrap"><table><thead><tr><th>时间</th><th>操作人</th><th>动作</th><th>资源</th><th>结果</th></tr></thead><tbody><tr v-for="a in audit" :key="a.id"><td>{{date(a.createdAt)}}</td><td>{{a.actor}}</td><td><code>{{a.action}}</code></td><td>{{a.resourceType}}<small class="mono">{{a.resourceId}}</small></td><td>{{a.outcome}}</td></tr></tbody></table></div><p v-if="!audit.length" class="table-empty">暂无审计记录。</p></section>
  <section v-else-if="page==='standard-certs'&&user.role==='ADMIN'">
    <StandardCertManager :key="projectId" :project-id="projectId" :is-admin="user.role==='ADMIN'" />
  </section>
  <section v-else-if="page==='users'&&user.role==='ADMIN'" class="panel"><div class="panel-heading"><h3>系统用户</h3><span class="muted">系统角色与项目角色独立管理</span></div><div class="table-wrap"><table><thead><tr><th>用户</th><th>系统角色</th><th>账号状态</th><th>创建时间</th><th>操作</th></tr></thead><tbody><tr v-for="u in users" :key="u.id"><td><strong>{{u.username}}</strong><small class="mono">{{u.id}}</small></td><td>{{u.role}}</td><td><span class="badge" :class="u.enabled===false?'bad':'good'">{{u.enabled===false?'已停用':'已启用'}}</span></td><td>{{date(u.createdAt)}}</td><td><button class="text-button" @click="openModal({kind:'editUser',title:'管理用户',user:u})">编辑权限 / 密码</button></td></tr></tbody></table></div><p v-if="!users.length" class="table-empty">暂无用户数据。</p></section>
  <footer class="workspace-footer"><span>GmSSL 密码工作空间</span><span>真实执行 · 项目隔离 · 操作留痕</span></footer>
  </main></div>
  <KeyGenerateDialog v-model:visible="showKeyGenDialog" :project-id="projectId" @generated="onKeyGeneratedInVault" />
  <div v-if="modal" class="modal-backdrop" @click.self="!busy&&(modal=null)"><section class="modal" role="dialog" aria-modal="true" aria-labelledby="modal-title"><div class="modal-heading"><h2 id="modal-title">{{modal.title}}</h2><button class="icon-button" aria-label="关闭对话框" :disabled="busy" @click="modal=null;form={};selectedFile=null"><X :size="20"/></button></div><form @submit.prevent="submitModal"><template v-if="modal.kind==='project'"><div class="field"><label>项目名称</label><input v-model="form.name" required maxlength="120"></div><div class="field"><label>项目描述</label><textarea v-model="form.description" rows="3" maxlength="1000"/></div></template><template v-if="['import','save'].includes(modal.kind)"><p v-if="modal.artifact" class="notice">产物：{{modal.artifact.name}} · {{bytes(modal.artifact.size)}}</p><div v-if="modal.kind==='import'" class="field"><label>密钥材料文件</label><input type="file" required @change="chooseFile"></div><div class="field-grid"><div class="field"><label>密钥名称</label><input v-model="form.name" required maxlength="120"></div><div class="field"><label>算法</label><input v-model="form.algorithm" required placeholder="如 SM2 / SM4" maxlength="80"></div><div class="field"><label>材料类型</label><select v-model="form.keyKind"><option v-for="k in (modal.kind==='save'&&modal.artifact?.statefulPrivate?['STATEFUL_PRIVATE_KEY']:kinds)" :key="k">{{k}}</option></select></div><div class="field"><label>实际文件编码</label><select v-model="form.encoding"><option v-for="encoding in ['PEM','DER','RAW','HEX','TEXT']" :key="encoding">{{encoding}}</option></select></div><div class="field wide"><label>用途</label><input v-model="form.usage" maxlength="200"></div><div class="field wide"><label>描述</label><textarea v-model="form.description" rows="2" maxlength="1000"/></div></div><p class="notice">请选择与材料一致的编码。导入不会自动证明密钥有效；状态型操作保护由工具目录决定。</p></template><template v-if="modal.kind==='export'||modal.kind==='delete'"><p>密钥：<strong>{{modal.key?.name}}</strong></p><p class="notice">{{modal.kind==='export'?'确认将原始托管材料下载至当前设备？下载受权限检查并记录审计。请妥善保管文件。':'删除后此项目将失去该托管材料。此操作不可撤回，请确认已有必要备份。'}}</p></template><template v-if="modal.kind==='fileDelete'"><p>确认删除输入材料 <strong>{{modal.fileName}}</strong>？现有引用将失效。</p></template><template v-if="modal.kind==='member'"><div class="field"><label>成员用户 ID</label><input v-model="form.userId" required pattern="[0-9a-fA-F-]{36}" placeholder="用户 UUID"><small>用户 ID 由系统管理员提供。</small></div><div class="field"><label>项目权限</label><select v-model="form.role"><option>VIEWER</option><option>EDITOR</option><option>OWNER</option></select></div><p class="notice">VIEWER 只读；EDITOR 可运行和管理材料；OWNER 可管理成员。最后一位所有者由服务端保护。</p></template><template v-if="modal.kind==='user'||modal.kind==='editUser'"><div v-if="modal.kind==='user'" class="field"><label>用户名</label><input v-model="form.username" required autocomplete="off" maxlength="80"></div><p v-else>正在编辑 <strong>{{modal.user?.username}}</strong></p><div class="field"><label>{{modal.kind==='user'?'初始密码':'重设密码（留空保持）'}}</label><input v-model="form.password" :required="modal.kind==='user'" type="password" autocomplete="new-password"><small>密码非空即可；秘密不保存至浏览器存储。</small></div><div class="field"><label>系统角色</label><select v-model="form.role"><option>USER</option><option>ADMIN</option></select></div><div v-if="modal.kind==='editUser'" class="field"><label>账号状态</label><select v-model="form.enabled"><option value="true">启用</option><option value="false">停用</option></select></div></template><p v-if="modalError" role="alert" class="error-message">{{modalError}}</p><div class="modal-actions"><button type="button" class="button secondary" :disabled="busy" @click="modal=null;form={};selectedFile=null">取消</button><button class="button" :class="['delete','fileDelete'].includes(modal.kind)?'danger-solid':'primary'" :disabled="busy">{{busy?'正在处理…':modal.kind==='export'?'确认下载':['delete','fileDelete'].includes(modal.kind)?'确认删除':'确认保存'}}</button></div></form></section></div>
</div>
</template>
