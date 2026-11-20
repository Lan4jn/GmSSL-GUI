<script setup lang="ts">
import { ref, computed, watch, onMounted } from 'vue'
import {
  FileKey2,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ArrowRight,
  ArrowLeft,
  ShieldCheck,
  KeyRound,
  FileText,
  Sliders,
  RotateCcw,
  Sparkles,
  Lock,
  ChevronDown,
  ChevronUp,
  X,
  Info,
  Download,
  ShieldAlert
} from 'lucide-vue-next'
import type { Key, ManagedFile, ProjectRole, KeyGenerationCapabilities, CertificateNode } from '../types'
import { download, errorMessage, getProjectCertificates } from '../api'
import {
  PROFILES,
  getDefaultDays,
  parseSanEntries,
  submitCertificateWorkflow,
  fetchKeyGenerationCapabilities,
  type CertificateProfile,
  type CertificatePurpose,
  type CertificateWorkflowRequest,
  type CertificateWorkflowResponse
} from '../certificate-wizard'

const props = withDefaults(
  defineProps<{
    projectId: string
    keys?: Key[]
    files?: ManagedFile[]
    capabilities?: KeyGenerationCapabilities
    role?: ProjectRole
    disabled?: boolean
    simpleMode?: boolean
  }>(),
  {
    keys: () => [],
    files: () => [],
    role: 'EDITOR',
    disabled: false,
    simpleMode: false
  }
)

const emit = defineEmits<{
  (e: 'close'): void
  (e: 'complete', result?: CertificateWorkflowResponse): void
  (e: 'navigate-vault'): void
  (e: 'error', message: string): void
}>()

// 步骤状态：1: 类型/用途, 2: 主体/SAN, 3: 密钥/发行者, 4: 有效期与确认
const currentStep = ref<number>(1)
const steps = [
  { id: 1, title: '证书类型' },
  { id: 2, title: '主体与 SAN' },
  { id: 3, title: '密钥与发行' },
  { id: 4, title: '有效期与确认' }
]

// 表单字段
const profile = ref<CertificateProfile>('SELF_SIGNED')
const certName = ref<string>('')
const purpose = ref<CertificatePurpose>('SERVER')

// Subject
const subjectCN = ref<string>('')
const subjectO = ref<string>('')
const subjectOU = ref<string>('')
const subjectC = ref<string>('')
const subjectST = ref<string>('')
const subjectL = ref<string>('')

// SAN 原始输入
const sanRaw = ref<string>('')

// 密钥配置
const keyMode = ref<'AUTO' | 'EXISTING'>('AUTO')
const provider = ref<'gmssl' | 'openssl'>('gmssl')
const userSelectedProvider = ref<boolean>(false)
const selectedKeyRef = ref<string>('')
const keyPassword = ref<string>('')

// 发行者配置（INTERMEDIATE_CA / CA_SIGN）
const issuerCertRef = ref<string>('')
const issuerKeyRef = ref<string>('')
const issuerPassword = ref<string>('')

// CSR 文件配置（CA_SIGN）
const csrFileRef = ref<string>('')

// 有效期与高级配置
const days = ref<number>(getDefaultDays('SELF_SIGNED'))
const showAdvanced = ref<boolean>(false)
const pathLenConstraint = ref<number | undefined>(undefined)
const sm2Id = ref<string>('')

// 执行状态
const submitting = ref<boolean>(false)
const workflowResponse = ref<CertificateWorkflowResponse | null>(null)
const executionError = ref<string>('')

// 内部加载的 capabilities
const loadedCapabilities = ref<KeyGenerationCapabilities | null>(null)

onMounted(async () => {
  if (!props.capabilities) {
    loadedCapabilities.value = await fetchKeyGenerationCapabilities()
  }
})

const effectiveCapabilities = computed<KeyGenerationCapabilities | null>(() => {
  return props.capabilities ?? loadedCapabilities.value
})

// Provider 可用性与状态解析
const providerStatus = computed(() => {
  const caps = effectiveCapabilities.value
  const gmsslCap = caps?.providers?.find(p => p.id === 'gmssl')
  const opensslCap = caps?.providers?.find(p => p.id === 'openssl')

  return {
    gmssl: {
      available: gmsslCap ? gmsslCap.available : true,
      reason: gmsslCap?.reason ?? ''
    },
    openssl: {
      available: opensslCap ? opensslCap.available : false,
      reason: opensslCap?.reason ?? '未检测到 OpenSSL 命令行或环境未配置'
    }
  }
})

// 仅在初始未由用户选择时，设置默认推荐引擎；严禁静默替换用户显式选定的引擎
watch(providerStatus, (status) => {
  if (!userSelectedProvider.value) {
    if (status.gmssl.available) {
      provider.value = 'gmssl'
    } else if (status.openssl.available) {
      provider.value = 'openssl'
    }
  }
}, { immediate: true })

function onProviderChange() {
  userSelectedProvider.value = true
}

// 监听 profile 变化，自动更新默认天数与名称提示
watch(profile, (newProfile) => {
  days.value = getDefaultDays(newProfile)
  const defaultPrefix = newProfile.toLowerCase().replace(/_/g, '-')
  const dateStr = new Date().toISOString().slice(0, 10)
  if (!certName.value || Object.keys(PROFILES).some(k => certName.value.startsWith(k.toLowerCase().replace(/_/g, '-'))) || Object.values(PROFILES).some(p => certName.value.startsWith(p.title))) {
    certName.value = `${defaultPrefix}-${dateStr}`
  }
  if (!subjectCN.value) {
    if (newProfile === 'ROOT_CA') subjectCN.value = 'GmSSL Root CA'
    else if (newProfile === 'INTERMEDIATE_CA') subjectCN.value = 'GmSSL Intermediate CA'
  }
}, { immediate: true })

// 当前 profile 元数据
const availableProfiles = computed(() => {
  if (props.simpleMode) {
    return [
      PROFILES.SELF_SIGNED,
      PROFILES.ROOT_CA,
      PROFILES.CSR,
      PROFILES.QUICK_ISSUE
    ]
  }
  return [
    PROFILES.SELF_SIGNED,
    PROFILES.ROOT_CA,
    PROFILES.INTERMEDIATE_CA,
    PROFILES.CSR,
    PROFILES.CA_SIGN,
    PROFILES.TLCP,
    PROFILES.QUICK_ISSUE
  ]
})

// 保证在 simpleMode 下不会残留中间 CA 或 TLCP
watch(
  () => props.simpleMode,
  (isSimple) => {
    if (isSimple && !['SELF_SIGNED', 'ROOT_CA', 'CSR', 'QUICK_ISSUE'].includes(profile.value)) {
      profile.value = 'SELF_SIGNED'
    }
  },
  { immediate: true }
)

function switchToRootCa() {
  profile.value = 'ROOT_CA'
  currentStep.value = 1
}

const profileMeta = computed(() => PROFILES[profile.value] || PROFILES.SELF_SIGNED)

// SAN 解析与校验
const parsedSan = computed(() => {
  if (!profileMeta.value.supportsSan || !sanRaw.value.trim()) {
    return { sanDns: [], sanIps: [], errors: [] }
  }
  const lines = sanRaw.value.split(/[,\n]/).map(s => s.trim()).filter(Boolean)
  return parseSanEntries(lines)
})

// 可用私钥材料列表
const availablePrivateKeys = computed(() => {
  return props.keys.filter(k => k.keyKind === 'PRIVATE_KEY' && !k.stateful)
})

// 严格按照证书扩展名与已知 mediaType 筛选可用 CA 证书文件
const CERT_EXTENSIONS = ['.crt', '.pem', '.cer']
const CERT_MEDIA_TYPES = ['application/x-x509-ca-cert', 'application/x-pem-file', 'application/pkix-cert']

const realCaNodes = ref<CertificateNode[]>([])
const caLoadFailed = ref(false)

async function loadRealCaCandidates() {
  if (!props.projectId) return
  caLoadFailed.value = false
  try {
    const res = await getProjectCertificates(props.projectId)
    realCaNodes.value = res?.nodes || []
  } catch {
    caLoadFailed.value = true
    realCaNodes.value = []
  }
}

watch(
  [() => props.projectId, () => profileMeta.value.requiresIssuer],
  ([pid, reqIssuer]) => {
    if (pid && reqIssuer) {
      loadRealCaCandidates()
    }
  },
  { immediate: true }
)

const availableCertFiles = computed(() => {
  // 优先依据后端真实证书拓扑 API：仅列出真实属于 CA、有效且允许签发的证书
  if (realCaNodes.value.length > 0) {
    const validCas = realCaNodes.value.filter(n => n.isCa && n.selectableAsIssuer && n.downloadRef)
    return validCas.map(n => ({
      id: n.downloadRef!.startsWith('file:') ? n.downloadRef!.slice(5) : n.downloadRef!,
      name: `${n.subjectCN} (${n.name})`,
      mediaType: 'application/x-x509-ca-cert',
      size: 0,
      createdAt: ''
    }))
  }
  // 回退或备用：若拓扑接口尚未返回或单测 mock 未注入，使用候选扩展名做基础筛选
  return props.files.filter(f => {
    const lower = f.name.toLowerCase()
    const extMatch = CERT_EXTENSIONS.some(ext => lower.endsWith(ext))
    const typeMatch = f.mediaType ? CERT_MEDIA_TYPES.includes(f.mediaType) : false
    return extMatch || typeMatch
  })
})

const selectedIssuerKey = computed(() => {
  return props.keys.find(k => `key:${k.id}` === issuerKeyRef.value)
})

const selectedKeyObj = computed(() => {
  return props.keys.find(k => `key:${k.id}` === selectedKeyRef.value)
})

// 步骤校验
const canProceed = computed(() => {
  if (currentStep.value === 1) {
    return !!profile.value
  }
  if (currentStep.value === 2) {
    if (profile.value === 'CA_SIGN') return true // CA_SIGN 的主体在 CSR 中已指定，CN 不在此强求
    if (!subjectCN.value.trim()) return false
    if (parsedSan.value.errors.length > 0) return false
    return true
  }
  if (currentStep.value === 3) {
    // 自动生成时，选中的 provider 必须可用，严禁静默切换或继续
    if (keyMode.value === 'AUTO' && !profileMeta.value.requiresCsr) {
      if (!providerStatus.value[provider.value]?.available) return false
    }
    if (profileMeta.value.requiresIssuer) {
      if (!issuerCertRef.value || !issuerKeyRef.value) return false
    }
    if (profileMeta.value.requiresCsr) {
      if (!csrFileRef.value) return false
    }
    if (keyMode.value === 'EXISTING' && !profileMeta.value.requiresCsr) {
      if (!selectedKeyRef.value) return false
    }
    return true
  }
  if (currentStep.value === 4) {
    return days.value > 0
  }
  return true
})

function nextStep() {
  if (canProceed.value && currentStep.value < 4) {
    currentStep.value++
  }
}

function prevStep() {
  if (currentStep.value > 1) {
    currentStep.value--
  }
}

// 构造提交参数
function buildPayload(): CertificateWorkflowRequest {
  const defaultName = `${profile.value.toLowerCase().replace(/_/g, '-')}-${new Date().toISOString().slice(0, 10)}`
  const rawName = certName.value.trim()
  // 后端 Jobs.java OUTPUT_FILE 严格校验 [A-Za-z0-9][A-Za-z0-9_.-]{0,119}
  const safeName = (rawName ? rawName.replace(/[^A-Za-z0-9_.-]/g, '_').replace(/^[^A-Za-z0-9]+/, '') : defaultName).slice(0, 80)

  const req: CertificateWorkflowRequest = {
    profile: profile.value,
    name: safeName || defaultName
  }

  // CA_SIGN 缺省 CN 时不强制发送 subject，有输入才附带
  if (profile.value !== 'CA_SIGN' || subjectCN.value.trim()) {
    req.subject = {
      CN: subjectCN.value.trim()
    }
    if (subjectC.value.trim()) req.subject.C = subjectC.value.trim()
    if (subjectO.value.trim()) req.subject.O = subjectO.value.trim()
    if (subjectOU.value.trim()) req.subject.OU = subjectOU.value.trim()
    if (subjectST.value.trim()) req.subject.ST = subjectST.value.trim()
    if (subjectL.value.trim()) req.subject.L = subjectL.value.trim()
  }

  if (profileMeta.value.supportsPurpose) {
    req.purpose = purpose.value
  }

  if (profileMeta.value.supportsSan && (parsedSan.value.sanDns.length > 0 || parsedSan.value.sanIps.length > 0)) {
    if (parsedSan.value.sanDns.length) req.sanDns = parsedSan.value.sanDns
    if (parsedSan.value.sanIps.length) req.sanIps = parsedSan.value.sanIps
  }

  if (profile.value !== 'CSR') {
    req.days = Number(days.value) || profileMeta.value.defaultDays
  }

  // 密钥设置
  if (keyMode.value === 'EXISTING' && selectedKeyRef.value) {
    req.keyRef = selectedKeyRef.value
    if (keyPassword.value) {
      req.keyPassword = keyPassword.value
    }
  } else {
    req.provider = provider.value
  }

  // 发行者设置
  if (profileMeta.value.requiresIssuer) {
    req.issuerCertRef = issuerCertRef.value
    req.issuerKeyRef = issuerKeyRef.value
    if (issuerPassword.value) {
      req.issuerPassword = issuerPassword.value
    }
  }

  // CSR 设置
  if (profileMeta.value.requiresCsr && csrFileRef.value) {
    req.csrRef = csrFileRef.value
  }

  // 高级设置
  const adv: Record<string, unknown> = {}
  if (pathLenConstraint.value !== undefined && pathLenConstraint.value >= 0) {
    adv.pathLenConstraint = Number(pathLenConstraint.value)
  }
  if (sm2Id.value.trim()) {
    adv.sm2Id = sm2Id.value.trim()
  }
  if (Object.keys(adv).length > 0) {
    req.advanced = adv
  }

  return req
}

// 提交工作流
async function executeWorkflow() {
  submitting.value = true
  executionError.value = ''
  workflowResponse.value = null

  try {
    const payload = buildPayload()
    const res = await submitCertificateWorkflow(props.projectId, payload)
    workflowResponse.value = res
    if (res.status === 'FAILED') {
      executionError.value = res.error || '证书签发工作流执行失败'
      emit('error', executionError.value)
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    executionError.value = msg
    emit('error', msg)
  } finally {
    submitting.value = false
  }
}

const downloadingFileId = ref<string>('')
const downloadError = ref<string>('')

const certFiles = computed(() => {
  if (!workflowResponse.value?.files) return []
  return workflowResponse.value.files.filter(f => !f.name.endsWith('_tlcp_keys.pem'))
})

const sensitiveFiles = computed(() => {
  if (!workflowResponse.value?.files) return []
  return workflowResponse.value.files.filter(f => f.name.endsWith('_tlcp_keys.pem'))
})

async function handleDownloadFile(f: ManagedFile) {
  if (downloadingFileId.value) return
  downloadingFileId.value = f.id
  downloadError.value = ''
  try {
    await download(`/projects/${props.projectId}/files/${f.id}/download`, f.name)
  } catch (err) {
    downloadError.value = errorMessage(err)
    emit('error', downloadError.value)
  } finally {
    downloadingFileId.value = ''
  }
}

async function handleDownloadSensitiveFile(f: ManagedFile) {
  if (downloadingFileId.value) return
  const confirmed = window.confirm(`文件 ${f.name} 包含敏感加密私钥材料，确认下载到本地设备？`)
  if (!confirmed) return
  await handleDownloadFile(f)
}

function handleNavigateVault() {
  emit('navigate-vault')
}

function handleDone() {
  emit('complete', workflowResponse.value ?? undefined)
}

function handleClose() {
  // 如果执行产生了部分材料，退出时也通知 parent 刷新列表
  if (workflowResponse.value && (workflowResponse.value.keys?.length || workflowResponse.value.files?.length)) {
    emit('complete', workflowResponse.value)
  } else {
    emit('close')
  }
}

function resetForm() {
  currentStep.value = 1
  workflowResponse.value = null
  executionError.value = ''
}
</script>

<template>
  <div class="cert-wizard">
    <!-- 头部导航与标题 -->
    <header class="wizard-header">
      <div class="header-title">
        <FileKey2 class="header-icon" :size="24" />
        <div>
          <h2>证书签发向导</h2>
          <p>遵循国密与 X.509 标准的分步证书快捷制作与签发中心</p>
        </div>
      </div>
      <button class="icon-button" title="关闭向导" aria-label="关闭向导" @click="handleClose">
        <X :size="20" />
      </button>
    </header>

    <!-- 工作流进行中或已产生结果视图 -->
    <div v-if="submitting || workflowResponse || executionError" class="execution-card">
      <div v-if="submitting" class="execution-loading">
        <Sparkles class="spin-icon" :size="32" />
        <h3>正在执行证书签发工作流…</h3>
        <p>正在由 GmSSL 执行真实密钥生成、证书签名、格式解析与链校验，请稍候。</p>
      </div>

      <div v-else-if="workflowResponse?.status === 'SUCCEEDED'" class="execution-success">
        <CheckCircle2 class="success-icon" :size="40" />
        <h3>证书签发成功！</h3>
        <p class="summary-text">工作流 ID: <code class="mono">{{ workflowResponse.workflowId }}</code></p>

        <!-- 显式呈现后端返回的真实执行警告与限制 -->
        <div v-if="workflowResponse?.warnings?.length" class="warnings-container">
          <div class="warnings-header">
            <AlertCircle :size="16" />
            <strong>系统执行告警与提示 ({{ workflowResponse.warnings.length }})</strong>
          </div>
          <ul class="warnings-list">
            <li v-for="(w, idx) in workflowResponse.warnings" :key="idx">{{ w }}</li>
          </ul>
        </div>

        <!-- 阶段状态列表 -->
        <div class="stages-container">
          <h4>执行阶段跟踪</h4>
          <div class="stages-list">
            <div v-for="stage in workflowResponse.stages" :key="stage.name" class="stage-item success">
              <span class="stage-indicator">✓</span>
              <span class="stage-name">{{ stage.name }}</span>
              <span class="stage-status badge good">成功</span>
              <small v-if="stage.jobId" class="mono job-id">任务 {{ stage.jobId.slice(0, 8) }}</small>
            </div>
          </div>
        </div>

        <!-- 下载失败告警 -->
        <div v-if="downloadError" class="banner error download-error-banner">
          <AlertCircle :size="16" />
          <span>{{ downloadError }}</span>
          <button class="icon-button" aria-label="关闭错误" @click="downloadError = ''">×</button>
        </div>

        <!-- 生成的材料清单与直接下载 -->
        <div class="artifacts-summary">
          <h4>可下载的证书与请求文件 (直接下载)</h4>
          <div v-if="certFiles.length" class="material-pills download-files-list">
            <div v-for="f in certFiles" :key="f.id" class="pill file-pill download-file-item">
              <FileText :size="14" />
              <div class="file-info">
                <span class="file-name"><strong>{{ f.name }}</strong></span>
                <span class="file-meta">{{ f.size ? (f.size < 1024 ? f.size + ' B' : (f.size / 1024).toFixed(1) + ' KiB') : '' }}</span>
              </div>
              <button
                type="button"
                class="button small secondary download-btn"
                :disabled="downloadingFileId === f.id"
                :aria-label="'下载证书 ' + f.name"
                @click="handleDownloadFile(f)"
              >
                <Download :size="14" />
                <span>{{ downloadingFileId === f.id ? '下载中…' : '下载' }}</span>
              </button>
            </div>
          </div>
          <div v-else class="empty-notice">
            <small class="muted">未生成公开证书文件</small>
          </div>

          <!-- 敏感私钥材料分组：明确警告，不混入普通证书下载 -->
          <div v-if="sensitiveFiles.length" class="sensitive-files-section">
            <h4 class="sensitive-title">
              <ShieldAlert :size="14" />
              <span>加密私钥材料 (敏感 · 独立授权)</span>
            </h4>
            <div class="material-pills">
              <div v-for="f in sensitiveFiles" :key="f.id" class="pill sensitive-pill">
                <Lock :size="14" />
                <div class="file-info">
                  <span class="file-name"><strong>{{ f.name }}</strong></span>
                  <span class="sensitive-tag">包含双私钥密文</span>
                </div>
                <button
                  type="button"
                  class="button small danger-outline download-btn"
                  :disabled="downloadingFileId === f.id"
                  :aria-label="'下载私钥材料 ' + f.name"
                  @click="handleDownloadSensitiveFile(f)"
                >
                  <Download :size="14" />
                  <span>{{ downloadingFileId === f.id ? '下载中…' : '下载私钥' }}</span>
                </button>
              </div>
            </div>
          </div>

          <!-- 密钥库已托管私钥提示 -->
          <div v-if="workflowResponse.keys?.length" class="vault-keys-section">
            <h4 class="vault-keys-title">
              <KeyRound :size="14" />
              <span>已自动安全托管至密钥库 (加密保护)</span>
            </h4>
            <div class="material-pills">
              <div v-for="k in workflowResponse.keys" :key="k.id" class="pill key-pill">
                <KeyRound :size="14" />
                <span>私钥：<strong>{{ k.name }}</strong> ({{ k.algorithm }}) · 状态: {{ k.validationStatus }}</span>
              </div>
            </div>
          </div>
        </div>

        <div class="wizard-actions">
          <button type="button" class="button secondary" @click="handleNavigateVault">
            <KeyRound :size="16" />
            <span>前往密钥库</span>
          </button>
          <button type="button" class="button primary" @click="handleDone">
            <span>完成并关闭</span> <ArrowRight :size="16" />
          </button>
        </div>
      </div>

      <div v-else class="execution-failure">
        <XCircle class="error-icon" :size="40" />
        <h3>证书工作流中断或失败</h3>
        <p class="error-message">{{ executionError || workflowResponse?.error || '执行过程中遇到错误' }}</p>

        <!-- 显式呈现执行告警 -->
        <div v-if="workflowResponse?.warnings?.length" class="warnings-container">
          <div class="warnings-header">
            <AlertCircle :size="16" />
            <strong>系统执行告警 ({{ workflowResponse.warnings.length }})</strong>
          </div>
          <ul class="warnings-list">
            <li v-for="(w, idx) in workflowResponse.warnings" :key="idx">{{ w }}</li>
          </ul>
        </div>

        <!-- 失败阶段展示 -->
        <div v-if="workflowResponse?.stages?.length" class="stages-container">
          <h4>执行进度跟踪</h4>
          <div class="stages-list">
            <div
              v-for="stage in workflowResponse.stages"
              :key="stage.name"
              class="stage-item"
              :class="{
                success: stage.status === 'SUCCEEDED',
                failed: stage.status === 'FAILED',
                pending: stage.status === 'PENDING' || stage.status === 'SKIPPED'
              }"
            >
              <span class="stage-indicator">{{ stage.status === 'SUCCEEDED' ? '✓' : stage.status === 'FAILED' ? '✗' : '—' }}</span>
              <span class="stage-name">{{ stage.name }}</span>
              <span
                class="stage-status badge"
                :class="stage.status === 'SUCCEEDED' ? 'good' : stage.status === 'FAILED' ? 'bad' : 'neutral'"
              >
                {{ stage.status === 'SUCCEEDED' ? '成功' : stage.status === 'FAILED' ? '失败' : '已跳过' }}
              </span>
            </div>
          </div>
        </div>

        <!-- 半成品材料提示 -->
        <div v-if="workflowResponse && (workflowResponse.keys?.length || workflowResponse.files?.length)" class="partial-notice">
          <AlertCircle :size="16" />
          <span>中断前已成功生成的材料（私钥或中间证书）已安全保存在项目中，未受损耗。</span>
        </div>

        <div class="wizard-actions">
          <button class="button secondary" @click="resetForm">
            <RotateCcw :size="16" /> 重新调整参数
          </button>
          <button
            v-if="workflowResponse && (workflowResponse.keys?.length || workflowResponse.files?.length)"
            class="button primary"
            @click="handleDone"
          >
            保留并查看已生成材料
          </button>
          <button class="button danger-outline" @click="handleClose">
            关闭向导
          </button>
        </div>
      </div>
    </div>

    <!-- 表单向导步骤视图 -->
    <div v-else class="wizard-body">
      <!-- 步骤指示器 -->
      <nav class="step-stepper" aria-label="向导步骤">
        <div
          v-for="s in steps"
          :key="s.id"
          class="step-item"
          :class="{ active: currentStep === s.id, done: currentStep > s.id }"
        >
          <span class="step-num">{{ currentStep > s.id ? '✓' : s.id }}</span>
          <span class="step-label">{{ s.title }}</span>
        </div>
      </nav>

      <form class="step-form" @submit.prevent="currentStep === 4 ? executeWorkflow() : nextStep()">
        <!-- 步骤 1：证书类型与用途 -->
        <section v-if="currentStep === 1" class="step-content">
          <div class="section-title">
            <h3>选择证书业务类型</h3>
            <p class="subtitle">根据您的实际部署场景，选择标准 X.509 或 TLCP 证书规格。</p>
          </div>

          <div class="profiles-grid">
            <label
              v-for="p in availableProfiles"
              :key="p.id"
              class="profile-card"
              :class="{ selected: profile === p.id }"
            >
              <input
                v-model="profile"
                type="radio"
                name="cert-profile"
                :value="p.id"
                class="sr-only"
              />
              <div class="card-header">
                <span class="profile-badge">{{ p.badge }}</span>
                <span v-if="p.isDualKey" class="dual-badge">双私钥双证书</span>
              </div>
              <strong class="profile-title">{{ p.title }}</strong>
              <p class="profile-desc">{{ p.description }}</p>
              <div class="profile-meta">
                <span>默认有效期: {{ p.defaultDays }} 天</span>
              </div>
            </label>
          </div>

          <!-- 用途选择（仅支持用途的类型） -->
          <div v-if="profileMeta.supportsPurpose" class="field purpose-field">
            <label>证书主要用途</label>
            <div class="purpose-options">
              <label class="radio-label">
                <input v-model="purpose" type="radio" value="SERVER" />
                <span>服务器证书 (SERVER)</span>
              </label>
              <label class="radio-label">
                <input v-model="purpose" type="radio" value="CLIENT" />
                <span>客户端证书 (CLIENT)</span>
              </label>
              <label class="radio-label">
                <input v-model="purpose" type="radio" value="SIGNING" />
                <span>代码/签名证书 (SIGNING)</span>
              </label>
            </div>
          </div>
        </section>

        <!-- 步骤 2：主体与 SAN 扩展 -->
        <section v-else-if="currentStep === 2" class="step-content">
          <div class="section-title">
            <h3>主体信息与域名绑定</h3>
            <p class="subtitle">配置证书的标识信息（Distinguished Name）与使用者可选名称（SAN）。</p>
          </div>

          <!-- CA_SIGN 特别说明 -->
          <div v-if="profile === 'CA_SIGN'" class="notice-info">
            <Info :size="16" />
            <span>CA 签发将严格复用 CSR 证书请求文件中已签名的主体标识 (Subject DN)，无需且不应在此重新输入 CN。</span>
          </div>

          <div v-else class="fields-grid">
            <div class="field full">
              <label for="subject-cn">
                通用名称 (CN / Common Name) <span class="required">*</span>
              </label>
              <input
                id="subject-cn"
                v-model="subjectCN"
                required
                maxlength="120"
                placeholder="例如：example.com 或 GmSSL CA Authority"
              />
              <small class="hint">证书代表的主域名或权威机构全名。</small>
            </div>

            <div class="field">
              <label for="subject-o">组织名称 (O / Organization)</label>
              <input id="subject-o" v-model="subjectO" maxlength="120" placeholder="例如：GmSSL Lab" />
            </div>

            <div class="field">
              <label for="subject-ou">部门单位 (OU / Organizational Unit)</label>
              <input id="subject-ou" v-model="subjectOU" maxlength="120" placeholder="例如：Security Dept" />
            </div>

            <div class="field">
              <label for="subject-c">国家/地区 (C / Country)</label>
              <input id="subject-c" v-model="subjectC" maxlength="2" placeholder="2 位代码，如 CN" />
            </div>

            <div class="field">
              <label for="subject-st">省/州 (ST / State)</label>
              <input id="subject-st" v-model="subjectST" maxlength="60" placeholder="如：Beijing" />
            </div>
          </div>

          <!-- SAN 输入（若支持） -->
          <div v-if="profileMeta.supportsSan" class="field full san-field">
            <label for="san-input">
              使用者可选名称 (SAN - 包含的域名与 IP 地址)
            </label>
            <textarea
              id="san-input"
              v-model="sanRaw"
              rows="3"
              placeholder="每行一个或逗号分隔，如：&#10;api.example.com&#10;*.service.cn&#10;localhost&#10;labnode&#10;192.168.1.100&#10;::1"
            />
            <div class="san-status">
              <span v-if="parsedSan.sanDns.length" class="badge good">DNS: {{ parsedSan.sanDns.join(', ') }}</span>
              <span v-if="parsedSan.sanIps.length" class="badge good">IP: {{ parsedSan.sanIps.join(', ') }}</span>
              <span v-if="parsedSan.errors.length" class="badge bad">{{ parsedSan.errors.join('；') }}</span>
              <small v-if="!sanRaw.trim()" class="hint">支持内网单标签主机名（如 localhost/labnode）、标准多级域名、Punycode 及 *.domain 规范通配符。</small>
            </div>

            <!-- IP SAN 显式提示 -->
            <div v-if="parsedSan.sanIps.length" class="notice-info ip-san-notice">
              <Info :size="15" />
              <span>证书与 CSR 支持 DNS、IPv4 和 IPv6 SAN 扩展；IP 地址按 iPAddress 类型编码，生成后可解析核对。</span>
            </div>
          </div>
        </section>

        <!-- 步骤 3：密钥管理与发行者选择 -->
        <section v-else-if="currentStep === 3" class="step-content">
          <div class="section-title">
            <h3>私钥配置与 CA 发行者</h3>
            <p class="subtitle">选择证书绑定的私钥来源以及用于签署该证书的发行者权威。</p>
          </div>

          <!-- 私钥生成方式（非 CA_SIGN） -->
          <div v-if="!profileMeta.requiresCsr" class="key-selection-block">
            <div class="field">
              <label>私钥生成方式</label>
              <div class="purpose-options">
                <label class="radio-label">
                  <input v-model="keyMode" type="radio" value="AUTO" />
                  <span>由向导自动生成并安全托管 SM2 私钥（免输口令，推荐）</span>
                </label>
                <label v-if="availablePrivateKeys.length" class="radio-label">
                  <input v-model="keyMode" type="radio" value="EXISTING" />
                  <span>使用项目中已有的托管私钥</span>
                </label>
              </div>
            </div>

            <!-- 自动生成时选择生成引擎（能力驱动禁用，禁止静默偷换） -->
            <div v-if="keyMode === 'AUTO'" class="field provider-field">
              <label>算法实现引擎</label>
              <select v-model="provider" @change="onProviderChange">
                <option value="gmssl">
                  GmSSL 原生国密引擎 {{ providerStatus.gmssl.available ? '(可用，推荐)' : `(不可用: ${providerStatus.gmssl.reason})` }}
                </option>
                <option value="openssl">
                  OpenSSL 引擎 {{ providerStatus.openssl.available ? '(可用)' : `(不可用: ${providerStatus.openssl.reason})` }}
                </option>
              </select>

              <!-- 显式禁止与错误警示，绝不静默替换 -->
              <div v-if="!providerStatus[provider]?.available" class="provider-error-alert">
                <AlertCircle :size="16" />
                <span>
                  当前选中的 <strong>{{ provider.toUpperCase() }}</strong> 引擎在本机环境中不可用（{{ providerStatus[provider]?.reason || '环境未配置' }}）。
                  系统严禁静默替换引擎进行冒充，请配置环境或手动切换为可用引擎。
                </span>
              </div>

              <small v-else class="hint">生成的私钥将默认使用 AES-256-GCM 加密托管并关联凭据，后续无需反复输入私钥口令。</small>
            </div>

            <!-- 选择已有私钥 -->
            <div v-else class="field">
              <label for="existing-key">选择现有私钥材料</label>
              <select id="existing-key" v-model="selectedKeyRef" required>
                <option value="">请选择私钥...</option>
                <option v-for="k in availablePrivateKeys" :key="k.id" :value="`key:${k.id}`">
                  {{ k.name }} ({{ k.algorithm }} - {{ k.id.slice(0, 8) }})
                </option>
              </select>
              <div v-if="selectedKeyObj?.hasManagedPassphrase" class="notice-managed">
                <Lock :size="14" />
                <span>该私钥口令已在平台托管加密，系统将自动填充，无需手动输入。</span>
              </div>
              <div v-else-if="selectedKeyRef" class="field pass-field">
                <label for="key-pass">私钥解密口令（非托管私钥）</label>
                <input id="key-pass" v-model="keyPassword" type="password" placeholder="请输入私钥解密口令" />
              </div>
            </div>
          </div>

          <!-- TLCP 双证提示 -->
          <div v-if="profileMeta.isDualKey" class="dual-key-notice">
            <ShieldCheck :size="20" />
            <div>
              <strong>TLCP 双证协议规范说明</strong>
              <p>向导将自动为该证书签发两对独立的 SM2 密钥（签名私钥与加密私钥）并分别签发签名证书与加密证书，严格符合 TLCP 规范。</p>
            </div>
          </div>

          <!-- CA_SIGN 需要提供 CSR -->
          <div v-if="profileMeta.requiresCsr" class="field full">
            <label for="csr-file">待签发的 CSR 请求文件材料 <span class="required">*</span></label>
            <select id="csr-file" v-model="csrFileRef" required>
              <option value="">请选择现有的 CSR 文件材料...</option>
              <option v-for="f in props.files" :key="f.id" :value="`file:${f.id}`">
                {{ f.name }} ({{ f.id.slice(0, 8) }})
              </option>
            </select>
          </div>

          <!-- 发行者配置（INTERMEDIATE_CA / CA_SIGN / QUICK_ISSUE） -->
          <div v-if="profileMeta.requiresIssuer" class="issuer-box">
            <h4>签署机构（Issuer CA）信息</h4>
            <div v-if="!availableCertFiles.length" class="banner warning no-ca-banner" style="margin-bottom: 1rem; display: flex; align-items: center; justify-content: space-between; gap: 0.75rem;">
              <div style="display: flex; align-items: center; gap: 0.5rem;">
                <AlertCircle :size="16" />
                <span>当前项目中暂无可用 CA 证书。请先创建根 CA 证书或自签服务证书，切勿自动创建根 CA 破坏权威。</span>
              </div>
              <button
                type="button"
                class="button small primary btn-create-root-ca"
                @click="switchToRootCa"
              >
                创建根 CA
              </button>
            </div>
            <div class="fields-grid">
              <div class="field">
                <label for="issuer-cert">CA 证书文件 <span class="required">*</span></label>
                <select id="issuer-cert" v-model="issuerCertRef" required>
                  <option value="">请选择 CA 证书文件...</option>
                  <option v-for="f in availableCertFiles" :key="f.id" :value="`file:${f.id}`">
                    {{ f.name }}
                  </option>
                </select>
                <small class="hint">按 .crt / .pem / .cer 筛选候选材料；最终由后端 GmSSL 真实解析为准。</small>
              </div>

              <div class="field">
                <label for="issuer-key">CA 签署私钥 <span class="required">*</span></label>
                <select id="issuer-key" v-model="issuerKeyRef" required>
                  <option value="">请选择 CA 私钥...</option>
                  <option v-for="k in availablePrivateKeys" :key="k.id" :value="`key:${k.id}`">
                    {{ k.name }} ({{ k.algorithm }})
                  </option>
                </select>
              </div>

              <div v-if="selectedIssuerKey?.hasManagedPassphrase" class="field full notice-managed">
                <Lock :size="14" />
                <span>CA 私钥口令已在平台加密托管，签发时将自动注入。</span>
              </div>

              <div v-else-if="issuerKeyRef" class="field full">
                <label for="issuer-pass">CA 私钥口令</label>
                <input id="issuer-pass" v-model="issuerPassword" type="password" placeholder="请输入 CA 私钥口令" />
              </div>
            </div>
          </div>
        </section>

        <!-- 步骤 4：有效期与确认 -->
        <section v-else class="step-content">
          <div class="section-title">
            <h3>有效期与参数确认</h3>
            <p class="subtitle">检查即将签署的证书配置，调整有效期限与受控高级参数。</p>
          </div>

          <div class="fields-grid">
            <div class="field">
              <label for="cert-name">工作流 / 证书保存名称 <span class="required">*</span></label>
              <input id="cert-name" v-model="certName" required maxlength="120" placeholder="例如：self-signed-cert" />
              <small class="hint">用于命名输出证书及密钥文件；自动转换为 ASCII，以字母或数字开头，可含点、下划线及连字符，最多 80 字符。</small>
            </div>

            <div v-if="profile !== 'CSR'" class="field">
              <label for="valid-days">有效天数 (Days) <span class="required">*</span></label>
              <input id="valid-days" v-model.number="days" type="number" min="1" max="7300" required />
              <small class="hint">推荐天数: {{ profileMeta.defaultDays }} 天</small>
            </div>
          </div>

          <!-- 高级参数折叠 -->
          <div class="advanced-section">
            <button
              type="button"
              class="text-button toggle-advanced"
              @click="showAdvanced = !showAdvanced"
            >
              <Sliders :size="15" />
              <span>高级选项 (受控白名单参数)</span>
              <component :is="showAdvanced ? ChevronUp : ChevronDown" :size="15" />
            </button>

            <div v-if="showAdvanced" class="advanced-fields fields-grid">
              <div v-if="['ROOT_CA', 'INTERMEDIATE_CA'].includes(profile)" class="field">
                <label for="path-len">Path Length 限制 (路径长度约束)</label>
                <input id="path-len" v-model.number="pathLenConstraint" type="number" min="0" max="10" placeholder="默认不限制" />
                <small class="hint">下级 CA 允许签发的最大证书链深度。</small>
              </div>

              <div class="field">
                <label for="sm2-id">SM2 签名身份标识 (SM2 ID)</label>
                <input id="sm2-id" v-model="sm2Id" placeholder="缺省为标准 1234567812345678" maxlength="128" />
              </div>
            </div>
          </div>

          <!-- 配置摘要清单 -->
          <div class="confirm-summary">
            <h4>证书签发配置摘要</h4>
            <dl class="summary-dl">
              <div><dt>证书类型</dt><dd><strong>{{ profileMeta.title }}</strong> ({{ profile }})</dd></div>
              <div><dt>通用名称 (CN)</dt><dd class="mono">{{ subjectCN || (profile === 'CA_SIGN' ? '复用 CSR 主体' : '—') }}</dd></div>
              <div v-if="profileMeta.supportsPurpose"><dt>业务用途</dt><dd>{{ purpose }}</dd></div>
              <div v-if="profile !== 'CSR'"><dt>有效期</dt><dd>{{ days }} 天</dd></div>
              <div><dt>私钥方式</dt><dd>{{ keyMode === 'AUTO' ? `自动生成 (${provider})` : `现有私钥 (${selectedKeyRef})` }}</dd></div>
              <div v-if="parsedSan.sanDns.length || parsedSan.sanIps.length">
                <dt>SAN 扩展</dt>
                <dd>
                  <span v-for="d in parsedSan.sanDns" :key="d" class="badge neutral">DNS:{{ d }}</span>
                  <span v-for="ip in parsedSan.sanIps" :key="ip" class="badge neutral">IP:{{ ip }}</span>
                </dd>
              </div>
            </dl>

            <div v-if="parsedSan.sanIps.length" class="notice-info ip-san-notice">
              <Info :size="14" />
              <span>支持 DNS、IPv4 和 IPv6 SAN 扩展；IP 地址将按 iPAddress 类型写入证书或 CSR。</span>
            </div>
          </div>
        </section>

        <!-- 底部导航操作按钮 -->
        <footer class="wizard-footer">
          <button
            v-if="currentStep > 1"
            type="button"
            class="button secondary"
            :disabled="submitting || props.disabled"
            @click="prevStep"
          >
            <ArrowLeft :size="16" /> 上一步
          </button>

          <button
            v-if="currentStep < 4"
            type="button"
            class="button primary"
            :disabled="!canProceed || props.disabled"
            @click="nextStep"
          >
            下一步 <ArrowRight :size="16" />
          </button>

          <button
            v-else
            type="submit"
            class="button primary execute-btn"
            :disabled="!canProceed || submitting || props.disabled"
          >
            <Sparkles :size="16" /> 开始签发证书
          </button>
        </footer>
      </form>
    </div>
  </div>
</template>

<style scoped>
.cert-wizard {
  background: var(--bg-surface, #ffffff);
  border: 1px solid var(--border-color, #e2e8f0);
  border-radius: 12px;
  overflow: hidden;
  box-shadow: 0 4px 16px rgba(0, 0, 0, 0.05);
  display: flex;
  flex-direction: column;
  margin-bottom: 2rem;
}

.wizard-header {
  padding: 1.25rem 1.5rem;
  background: linear-gradient(to right, #0f766e, #115e59);
  color: #ffffff;
  display: flex;
  align-items: center;
  justify-content: space-between;
}

.header-title {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.header-title h2 {
  font-size: 1.15rem;
  font-weight: 600;
  margin: 0;
  line-height: 1.3;
}

.header-title p {
  font-size: 0.825rem;
  opacity: 0.85;
  margin: 0;
}

.step-stepper {
  display: flex;
  background: #f8fafc;
  border-bottom: 1px solid #e2e8f0;
  padding: 0.75rem 1.5rem;
  gap: 1.5rem;
  overflow-x: auto;
}

.step-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  color: #64748b;
  font-size: 0.875rem;
  white-space: nowrap;
}

.step-item.active {
  color: #0f766e;
  font-weight: 600;
}

.step-item.done {
  color: #047857;
}

.step-num {
  width: 22px;
  height: 22px;
  border-radius: 50%;
  background: #e2e8f0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  font-size: 0.75rem;
  font-weight: bold;
}

.step-item.active .step-num {
  background: #0f766e;
  color: #ffffff;
}

.step-item.done .step-num {
  background: #10b981;
  color: #ffffff;
}

.wizard-body {
  padding: 1.5rem;
}

.section-title {
  margin-bottom: 1.25rem;
}

.section-title h3 {
  font-size: 1.05rem;
  font-weight: 600;
  color: #1e293b;
  margin: 0 0 0.25rem 0;
}

.subtitle {
  font-size: 0.85rem;
  color: #64748b;
  margin: 0;
}

.notice-info {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  background: #eff6ff;
  border: 1px solid #bfdbfe;
  border-radius: 6px;
  padding: 0.75rem 1rem;
  color: #1d4ed8;
  font-size: 0.875rem;
  margin-bottom: 1.25rem;
}

.ip-san-notice {
  margin-top: 0.5rem;
  margin-bottom: 0;
  padding: 0.5rem 0.75rem;
  font-size: 0.8rem;
  background: #fffbeb;
  border-color: #fde68a;
  color: #92400e;
}

.provider-error-alert {
  display: flex;
  align-items: flex-start;
  gap: 0.5rem;
  margin-top: 0.4rem;
  padding: 0.5rem 0.75rem;
  border-radius: 6px;
  background: #fef2f2;
  border: 1px solid #fecaca;
  color: #b91c1c;
  font-size: 0.8rem;
  line-height: 1.4;
}

.warnings-container {
  max-width: 480px;
  margin: 1rem auto;
  text-align: left;
  background: #fffbeb;
  border: 1px solid #fde68a;
  border-radius: 8px;
  padding: 0.85rem;
  color: #92400e;
}

.warnings-header {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.85rem;
  margin-bottom: 0.4rem;
}

.warnings-list {
  margin: 0;
  padding-left: 1.25rem;
  font-size: 0.8rem;
  line-height: 1.4;
}

.profiles-grid {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(280px, 1fr));
  gap: 1rem;
  margin-bottom: 1.5rem;
}

.profile-card {
  border: 1.5px solid #e2e8f0;
  border-radius: 8px;
  padding: 1rem;
  cursor: pointer;
  transition: all 0.15s ease;
  display: flex;
  flex-direction: column;
  background: #ffffff;
}

.profile-card:hover {
  border-color: #14b8a6;
}

.profile-card.selected {
  border-color: #0f766e;
  background: #f0fdfa;
  box-shadow: 0 0 0 1px #0f766e;
}

.card-header {
  display: flex;
  gap: 0.5rem;
  margin-bottom: 0.5rem;
}

.profile-badge {
  font-size: 0.75rem;
  background: #ccfbf1;
  color: #0f766e;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-weight: 500;
}

.dual-badge {
  font-size: 0.75rem;
  background: #e0e7ff;
  color: #4338ca;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-weight: 500;
}

.profile-title {
  font-size: 0.95rem;
  color: #0f172a;
  margin-bottom: 0.35rem;
}

.profile-desc {
  font-size: 0.825rem;
  color: #64748b;
  margin: 0 0 0.75rem 0;
  flex-grow: 1;
  line-height: 1.4;
}

.profile-meta {
  font-size: 0.75rem;
  color: #94a3b8;
  border-top: 1px dashed #e2e8f0;
  padding-top: 0.5rem;
}

.fields-grid {
  display: grid;
  grid-template-columns: repeat(2, 1fr);
  gap: 1rem;
}

@media (max-width: 640px) {
  .fields-grid {
    grid-template-columns: 1fr;
  }
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.field.full {
  grid-column: 1 / -1;
}

.field label {
  font-size: 0.85rem;
  font-weight: 500;
  color: #334155;
}

.required {
  color: #dc2626;
}

.field input,
.field select,
.field textarea {
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  padding: 0.55rem 0.75rem;
  font-size: 0.875rem;
  color: #1e293b;
  background: #ffffff;
  outline: none;
}

.field input:focus,
.field select:focus,
.field textarea:focus {
  border-color: #0f766e;
  box-shadow: 0 0 0 2px rgba(15, 118, 110, 0.15);
}

.hint {
  font-size: 0.75rem;
  color: #64748b;
}

.purpose-options {
  display: flex;
  flex-wrap: wrap;
  gap: 1rem;
  margin-top: 0.25rem;
}

.radio-label {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.85rem;
  color: #334155;
  cursor: pointer;
}

.san-status {
  display: flex;
  flex-wrap: wrap;
  gap: 0.5rem;
  margin-top: 0.4rem;
}

.badge {
  display: inline-block;
  padding: 0.2rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  font-weight: 500;
}

.badge.good {
  background: #d1fae5;
  color: #065f46;
}

.badge.bad {
  background: #fee2e2;
  color: #991b1b;
}

.badge.neutral {
  background: #f1f5f9;
  color: #475569;
}

.notice-managed {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.5rem 0.75rem;
  background: #f0fdfa;
  border: 1px solid #99f6e4;
  border-radius: 6px;
  font-size: 0.8rem;
  color: #0f766e;
  margin-top: 0.35rem;
}

.dual-key-notice {
  display: flex;
  gap: 0.75rem;
  background: #eef2ff;
  border: 1px solid #c7d2fe;
  border-radius: 8px;
  padding: 0.85rem;
  color: #3730a3;
  margin-top: 1rem;
}

.issuer-box {
  margin-top: 1.25rem;
  border-top: 1px solid #e2e8f0;
  padding-top: 1.25rem;
}

.issuer-box h4 {
  font-size: 0.95rem;
  color: #1e293b;
  margin: 0 0 0.85rem 0;
}

.advanced-section {
  margin-top: 1rem;
  border-top: 1px dashed #e2e8f0;
  padding-top: 0.75rem;
}

.toggle-advanced {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  color: #0f766e;
  font-size: 0.85rem;
  cursor: pointer;
  background: none;
  border: none;
  padding: 0.25rem 0;
}

.advanced-fields {
  margin-top: 0.75rem;
  padding: 0.75rem;
  background: #f8fafc;
  border-radius: 6px;
}

.confirm-summary {
  margin-top: 1.25rem;
  background: #f8fafc;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 1rem;
}

.confirm-summary h4 {
  margin: 0 0 0.75rem 0;
  font-size: 0.9rem;
  color: #334155;
}

.summary-dl {
  display: grid;
  grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
  gap: 0.75rem;
  margin: 0;
}

.summary-dl dt {
  font-size: 0.75rem;
  color: #64748b;
}

.summary-dl dd {
  font-size: 0.85rem;
  color: #1e293b;
  margin: 0.15rem 0 0 0;
}

.mono {
  font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
}

.wizard-footer {
  margin-top: 1.5rem;
  display: flex;
  justify-content: flex-end;
  gap: 0.75rem;
  border-top: 1px solid #e2e8f0;
  padding-top: 1.25rem;
}

.button {
  display: inline-flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.55rem 1rem;
  border-radius: 6px;
  font-size: 0.875rem;
  font-weight: 500;
  cursor: pointer;
  border: 1px solid transparent;
  transition: all 0.15s ease;
}

.button.primary {
  background: #0f766e;
  color: #ffffff;
}

.button.primary:hover:not(:disabled) {
  background: #115e59;
}

.button.secondary {
  background: #f1f5f9;
  color: #334155;
  border-color: #cbd5e1;
}

.button.secondary:hover:not(:disabled) {
  background: #e2e8f0;
}

.button.danger-outline {
  background: #ffffff;
  color: #dc2626;
  border-color: #fca5a5;
}

.button.danger-outline:hover:not(:disabled) {
  background: #fef2f2;
}

.button:disabled {
  opacity: 0.5;
  cursor: not-allowed;
}

.icon-button {
  background: none;
  border: none;
  color: inherit;
  cursor: pointer;
  padding: 0.25rem;
  border-radius: 4px;
}

.icon-button:hover {
  background: rgba(255, 255, 255, 0.15);
}

.sr-only {
  position: absolute;
  width: 1px;
  height: 1px;
  padding: 0;
  margin: -1px;
  overflow: hidden;
  clip: rect(0, 0, 0, 0);
  border: 0;
}

/* 执行卡片样式 */
.execution-card {
  padding: 2.5rem 1.5rem;
  text-align: center;
}

.execution-loading .spin-icon {
  color: #0f766e;
  animation: spin 2s linear infinite;
  margin-bottom: 1rem;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.execution-success .success-icon {
  color: #10b981;
  margin-bottom: 0.5rem;
}

.execution-failure .error-icon {
  color: #ef4444;
  margin-bottom: 0.5rem;
}

.stages-container {
  max-width: 480px;
  margin: 1.5rem auto;
  text-align: left;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  padding: 1rem;
  background: #f8fafc;
}

.stages-container h4 {
  margin: 0 0 0.75rem 0;
  font-size: 0.875rem;
  color: #475569;
}

.stages-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.stage-item {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  font-size: 0.85rem;
  padding: 0.35rem 0.5rem;
  border-radius: 4px;
  background: #ffffff;
  border: 1px solid #e2e8f0;
}

.stage-item.success {
  border-color: #a7f3d0;
}

.stage-item.failed {
  border-color: #fecaca;
  background: #fef2f2;
}

.stage-indicator {
  font-weight: bold;
  width: 16px;
  text-align: center;
}

.stage-name {
  flex-grow: 1;
  color: #1e293b;
}

.job-id {
  color: #94a3b8;
  font-size: 0.75rem;
}

.artifacts-summary {
  max-width: 480px;
  margin: 1rem auto 1.5rem;
  text-align: left;
}

.artifacts-summary h4 {
  margin: 0 0 0.5rem 0;
  font-size: 0.85rem;
  color: #475569;
}

.material-pills {
  display: flex;
  flex-direction: column;
  gap: 0.4rem;
}

.pill {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  padding: 0.4rem 0.75rem;
  border-radius: 6px;
  font-size: 0.825rem;
}

.pill.key-pill {
  background: #fef3c7;
  color: #92400e;
}

.pill.file-pill {
  background: #e0f2fe;
  color: #0369a1;
}

.partial-notice {
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 0.4rem;
  color: #b45309;
  font-size: 0.85rem;
  margin: 1rem 0;
}

.wizard-actions {
  display: flex;
  justify-content: center;
  gap: 1rem;
  margin-top: 1.5rem;
}

.download-error-banner {
  margin: 1rem auto;
  max-width: 480px;
}

.download-file-item {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.75rem;
}

.file-info {
  display: flex;
  flex-direction: column;
  flex-grow: 1;
  margin-left: 0.5rem;
}

.file-name {
  font-weight: 500;
  word-break: break-all;
}

.file-meta {
  font-size: 0.75rem;
  color: #64748b;
}

.download-btn {
  margin-left: 0.5rem;
  flex-shrink: 0;
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
}

.sensitive-files-section {
  margin-top: 1.25rem;
  padding: 0.75rem;
  border: 1px dashed #f59e0b;
  border-radius: 8px;
  background: #fffbeb;
}

.sensitive-title {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  color: #b45309 !important;
  font-weight: 600;
  margin: 0 0 0.5rem 0 !important;
}

.sensitive-pill {
  background: #fef3c7;
  color: #92400e;
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.5rem 0.75rem;
}

.sensitive-tag {
  font-size: 0.7rem;
  background: #fde68a;
  color: #78350f;
  padding: 0.1rem 0.35rem;
  border-radius: 3px;
  margin-top: 0.15rem;
  display: inline-block;
  width: fit-content;
}

.vault-keys-section {
  margin-top: 1.25rem;
  padding: 0.75rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
  background: #f8fafc;
}

.vault-keys-title {
  display: flex;
  align-items: center;
  gap: 0.35rem;
  color: #475569 !important;
  font-weight: 600;
  margin: 0 0 0.5rem 0 !important;
}

</style>
