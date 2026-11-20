<script setup lang="ts">
import { ref, computed, onMounted, watch } from 'vue'
import {
  FileKey2,
  ShieldCheck,
  Search,
  RefreshCw,
  Copy,
  Download,
  AlertTriangle,
  Check,
  ChevronLeft,
  ChevronRight,
  PlusCircle,
  XCircle,
  FileText
} from 'lucide-vue-next'
import {
  listStandardCertificates,
  issueStandardCertificate,
  revokeStandardCertificate,
  errorMessage
} from '../api'
import type { StandardClientCertificate } from '../types'

const props = withDefaults(
  defineProps<{
    projectId: string
    isAdmin?: boolean
  }>(),
  {
    isAdmin: true
  }
)

const emit = defineEmits<{
  (e: 'updated'): void
}>()

// Data state
const certs = ref<StandardClientCertificate[]>([])
const total = ref(0)
const page = ref(0)
const size = ref(50)
const searchFingerprint = ref('')
const loading = ref(false)
const loadError = ref('')
const isServiceDown = ref(false)

// Issue form state
const deviceLabel = ref('')
const csrPem = ref('')
const activeRequestId = ref('')
const issuing = ref(false)
const formError = ref('')
const formSuccess = ref('')

// Revoke modal state
const revokingCert = ref<StandardClientCertificate | null>(null)
const revoking = ref(false)
const revokeError = ref('')
const revokeSuccess = ref('')

// Copy feedback
const copiedFeedback = ref<{ text: string; id: string } | null>(null)
let copyTimer: ReturnType<typeof setTimeout> | null = null

function generateRequestId(): string {
  if (typeof crypto !== 'undefined' && typeof crypto.randomUUID === 'function') {
    return crypto.randomUUID()
  }
  return `req-${Date.now()}-${Math.random().toString(36).substring(2, 9)}`
}

function getOrReuseRequestId(): string {
  if (!activeRequestId.value) {
    activeRequestId.value = generateRequestId()
  }
  return activeRequestId.value
}

const totalPages = computed(() => Math.ceil(total.value / size.value) || 1)

function isExpired(cert: StandardClientCertificate): boolean {
  return cert.status === 'EXPIRED' || Date.now() > cert.expiresAt
}

function formatDate(epochMs: number): string {
  if (!epochMs) return '—'
  return new Date(epochMs).toLocaleString('zh-CN', { hour12: false })
}

function copyToClipboard(text: string, id: string) {
  if (!text) return
  if (navigator.clipboard && navigator.clipboard.writeText) {
    navigator.clipboard.writeText(text).catch(() => fallbackCopy(text))
  } else {
    fallbackCopy(text)
  }
  if (copyTimer) clearTimeout(copyTimer)
  copiedFeedback.value = { text: '已复制到剪贴板', id }
  copyTimer = setTimeout(() => {
    copiedFeedback.value = null
  }, 2500)
}

function fallbackCopy(text: string) {
  const ta = document.createElement('textarea')
  ta.value = text
  ta.style.position = 'fixed'
  ta.style.left = '-9999px'
  document.body.appendChild(ta)
  ta.focus()
  ta.select()
  try {
    document.execCommand('copy')
  } catch {
    // Ignore fallback copy error
  }
  document.body.removeChild(ta)
}

function downloadText(content: string, filename: string) {
  const blob = new Blob([content], { type: 'application/x-pem-file;charset=utf-8' })
  const url = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = url
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  setTimeout(() => URL.revokeObjectURL(url), 1000)
}

function downloadCert(cert: StandardClientCertificate) {
  const name = (cert.deviceLabel || cert.serial || 'client').replace(/[^a-zA-Z0-9_-]/g, '_')
  downloadText(cert.certificatePem, `${name}-cert.pem`)
}

function downloadChain(cert: StandardClientCertificate) {
  if (!cert.chainPem) return
  const name = (cert.deviceLabel || cert.serial || 'client').replace(/[^a-zA-Z0-9_-]/g, '_')
  downloadText(cert.chainPem, `${name}-chain.pem`)
}

async function loadCertificates() {
  if (!props.projectId) return
  loading.value = true
  loadError.value = ''
  isServiceDown.value = false
  try {
    const res = await listStandardCertificates(props.projectId, {
      fingerprint: searchFingerprint.value.trim() || undefined,
      page: page.value,
      size: size.value
    })
    certs.value = res.items || []
    total.value = res.total || 0
  } catch (e: any) {
    loadError.value = errorMessage(e)
    if (e?.status === 0 || e?.code === 'NETWORK_ERROR' || e?.status === 503) {
      isServiceDown.value = true
      loadError.value = '服务异常或已停服，无法连接证书签发服务'
    }
  } finally {
    loading.value = false
  }
}

function handleSearch() {
  page.value = 0
  loadCertificates()
}

function handlePageChange(newPage: number) {
  if (newPage < 0 || newPage >= totalPages.value) return
  page.value = newPage
  loadCertificates()
}

async function handleIssue() {
  if (issuing.value) return
  formError.value = ''
  formSuccess.value = ''

  const label = deviceLabel.value.trim()
  if (!label) {
    formError.value = '请输入客户端或设备标识名称'
    return
  }

  const rawCsr = csrPem.value.trim()
  if (!rawCsr) {
    formError.value = '请输入 CSR 签名请求内容'
    return
  }

  // 1. 严格禁止输入私钥
  const privateKeyMarkers = [
    'BEGIN PRIVATE KEY',
    'BEGIN EC PRIVATE KEY',
    'BEGIN RSA PRIVATE KEY',
    'BEGIN ENCRYPTED PRIVATE KEY',
    'BEGIN OPENSSH PRIVATE KEY'
  ]
  if (/PRIVATE KEY/i.test(label) || privateKeyMarkers.some(marker => rawCsr.toUpperCase().includes(marker))) {
    formError.value = '严禁输入私钥材料！平台仅接受标准客户端证书签名请求（CSR，以 -----BEGIN CERTIFICATE REQUEST----- 开头）'
    return
  }

  // 2. 校验 CSR 格式有效性
  const isCsr = /^-----BEGIN CERTIFICATE REQUEST-----\r?\n(?:[A-Za-z0-9+/=]+\r?\n)+-----END CERTIFICATE REQUEST-----$/.test(rawCsr)
  if (!isCsr) {
    formError.value = '无效的 CSR 签名请求 PEM 格式，请检查证书请求头尾及内容。'
    return
  }

  issuing.value = true
  const reqId = getOrReuseRequestId()

  try {
    const res = await issueStandardCertificate(props.projectId, {
      requestId: reqId,
      csrPem: rawCsr,
      deviceLabel: label
    })
    formSuccess.value = `证书签发成功！设备：${res.deviceLabel}，指纹：${res.fingerprint}`
    // 签发成功后重置表单和 requestId
    activeRequestId.value = ''
    deviceLabel.value = ''
    csrPem.value = ''
    emit('updated')
    await loadCertificates()
  } catch (e: any) {
    // 失败时不清除 activeRequestId，以支持断线重试复用 requestId
    formError.value = `签发失败：${errorMessage(e)}`
  } finally {
    issuing.value = false
  }
}

function openRevokeModal(cert: StandardClientCertificate) {
  revokingCert.value = cert
  revokeError.value = ''
}

async function confirmRevoke() {
  if (!revokingCert.value || revoking.value) return
  revoking.value = true
  revokeError.value = ''
  try {
    const updated = await revokeStandardCertificate(props.projectId, revokingCert.value.id)
    revokeSuccess.value = `证书 ${updated.deviceLabel}（序列号 ${updated.serial}）已成功吊销`
    // 更新本地列表中该条目状态
    const idx = certs.value.findIndex(c => c.id === updated.id)
    if (idx !== -1) {
      certs.value[idx] = updated
    }
    revokingCert.value = null
    emit('updated')
  } catch (e: any) {
    revokeError.value = `吊销失败：${errorMessage(e)}`
  } finally {
    revoking.value = false
  }
}

watch([deviceLabel, csrPem], () => { activeRequestId.value = '' })

watch(
  () => props.projectId,
  () => {
    page.value = 0
    searchFingerprint.value = ''
    formError.value = ''
    formSuccess.value = ''
    activeRequestId.value = ''
    loadCertificates()
  }
)

onMounted(() => {
  loadCertificates()
})
</script>

<template>
  <div class="standard-cert-manager">
    <!-- 头部说明条 -->
    <div class="admin-banner">
      <div class="banner-title">
        <ShieldCheck :size="20" class="icon-accent" />
        <div>
          <h3>标准客户端证书管理 (按项目)</h3>
          <p>
            集中颁发与管理客户端 mTLS 认证证书台账。只接受客户端 CSR 签名请求，严禁上传或录入私钥。
          </p>
        </div>
      </div>
      <div v-if="copiedFeedback" class="copy-alert" role="status">
        <Check :size="16" /> {{ copiedFeedback.text }}
      </div>
    </div>

    <!-- 停服或网络异常警报 -->
    <div v-if="isServiceDown" class="banner error service-down" role="alert">
      <AlertTriangle :size="20" />
      <div class="alert-content">
        <strong>服务异常或已停服</strong>
        <p>无法连接客户端证书后端签发中心，请确认后台服务状态与网络通信。</p>
      </div>
      <button
        type="button"
        class="button small secondary"
        data-test="retry-load-btn"
        :disabled="loading"
        @click="loadCertificates"
      >
        <RefreshCw :size="14" :class="{ spinning: loading }" /> 重试连接
      </button>
    </div>

    <!-- 快速发证表单（仅管理员可见） -->
    <section v-if="isAdmin" class="panel issue-panel">
      <div class="panel-heading">
        <div class="heading-with-icon">
          <PlusCircle :size="18" class="icon-accent" />
          <h4>快速签发客户端证书</h4>
        </div>
        <span class="badge neutral">断线防重保护</span>
      </div>

      <div class="issue-form">
        <div class="field">
          <label for="device-label">设备或客户端标识 <span class="required">*</span></label>
          <input
            id="device-label"
            v-model="deviceLabel"
            data-test="device-label-input"
            type="text"
            placeholder="例如：Finance-Terminal-01 或 App-Client-Prod"
            maxlength="100"
            :disabled="issuing"
          />
        </div>

        <div class="field">
          <label for="csr-pem">
            客户端证书签名请求 (CSR PEM) <span class="required">*</span>
            <span class="sub-tip">使用 RSA 3072 位密钥，以 SHA-256 签署 CSR；请勿粘贴私钥。</span>
          </label>
          <textarea
            id="csr-pem"
            v-model="csrPem"
            data-test="csr-pem-input"
            rows="5"
            placeholder="-----BEGIN CERTIFICATE REQUEST-----&#10;...&#10;-----END CERTIFICATE REQUEST-----"
            :disabled="issuing"
          ></textarea>
        </div>

        <div v-if="activeRequestId" class="request-id-hint">
          <FileText :size="14" />
          <span>断线重试保护生效中：当前请求标识 <code>{{ activeRequestId }}</code></span>
        </div>

        <div v-if="formError" class="banner error" role="alert">
          <AlertTriangle :size="16" />
          <span>{{ formError }}</span>
        </div>

        <div v-if="formSuccess" class="banner success" role="status">
          <Check :size="16" />
          <span>{{ formSuccess }}</span>
        </div>

        <div class="form-actions">
          <button
            type="button"
            class="button primary"
            data-test="submit-issue-btn"
            :disabled="issuing || !projectId"
            @click="handleIssue"
          >
            <ShieldCheck :size="16" />
            {{ issuing ? '正在签发证书…' : '提交并签发证书' }}
          </button>
        </div>
      </div>
    </section>

    <!-- 证书查询与台账列表 -->
    <section class="panel list-panel">
      <div class="panel-heading">
        <div class="search-box">
          <Search :size="16" class="search-icon" />
          <input
            v-model="searchFingerprint"
            data-test="search-fingerprint-input"
            type="text"
            placeholder="按证书指纹模糊过滤…"
            @keyup.enter="handleSearch"
          />
          <button
            type="button"
            class="button small secondary"
            data-test="search-btn"
            :disabled="loading"
            @click="handleSearch"
          >
            查询
          </button>
        </div>
        <div class="actions">
          <button
            type="button"
            class="icon-button"
            title="刷新列表"
            :disabled="loading"
            @click="loadCertificates"
          >
            <RefreshCw :size="16" :class="{ spinning: loading }" />
          </button>
          <span class="count-badge">共 {{ total }} 张证书</span>
        </div>
      </div>

      <div v-if="loadError && !isServiceDown" class="banner error">
        {{ loadError }}
      </div>

      <div v-if="revokeSuccess" class="banner success">
        <Check :size="16" />
        <span>{{ revokeSuccess }}</span>
      </div>

      <div class="table-wrap">
        <table class="cert-table">
          <thead>
            <tr>
              <th>设备标识 / 序列号</th>
              <th>证书指纹 (SHA-256)</th>
              <th>到期时间</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="cert in certs" :key="cert.id">
              <td>
                <div class="device-cell">
                  <strong>{{ cert.deviceLabel }}</strong>
                  <small class="mono">SN: {{ cert.serial }}</small>
                </div>
              </td>
              <td>
                <div class="fingerprint-cell">
                  <code class="mono fp-code">{{ cert.fingerprint }}</code>
                  <button
                    type="button"
                    class="icon-button small copy-btn"
                    data-test="copy-fingerprint-btn"
                    title="复制指纹"
                    @click="copyToClipboard(cert.fingerprint, `fp-${cert.id}`)"
                  >
                    <Copy :size="14" />
                  </button>
                </div>
              </td>
              <td>
                <span :class="{ 'text-danger': isExpired(cert) }">
                  {{ formatDate(cert.expiresAt) }}
                </span>
              </td>
              <td>
                <span
                  class="badge"
                  :class="{
                    good: cert.status === 'VALID' && !isExpired(cert),
                    bad: cert.status === 'REVOKED' || cert.status === 'EXPIRED' || isExpired(cert)
                  }"
                >
                  {{ cert.status === 'REVOKED' ? '已吊销' : isExpired(cert) ? '已过期' : '正常' }}
                </span>
              </td>
              <td>
                <div class="row-actions">
                  <button
                    type="button"
                    class="button small secondary"
                    data-test="copy-cert-btn"
                    title="复制证书 PEM"
                    @click="copyToClipboard(cert.certificatePem, `cert-${cert.id}`)"
                  >
                    <Copy :size="14" /> 证书
                  </button>
                  <button
                    type="button"
                    class="button small secondary"
                    data-test="download-cert-btn"
                    title="下载证书 PEM 文件"
                    @click="downloadCert(cert)"
                  >
                    <Download :size="14" /> 证书
                  </button>
                  <button
                    v-if="cert.chainPem"
                    type="button"
                    class="button small secondary"
                    data-test="download-chain-btn"
                    title="下载完整证书链 PEM 文件"
                    @click="downloadChain(cert)"
                  >
                    <Download :size="14" /> 证书链
                  </button>
                  <button
                    v-if="cert.status === 'VALID' && !isExpired(cert) && isAdmin"
                    type="button"
                    class="button small danger"
                    data-test="open-revoke-btn"
                    title="吊销该客户端证书"
                    @click="openRevokeModal(cert)"
                  >
                    <XCircle :size="14" /> 吊销
                  </button>
                </div>
              </td>
            </tr>
            <tr v-if="certs.length === 0 && !loading">
              <td colspan="5" class="empty-cell">
                <div class="empty-state">
                  <FileKey2 :size="32" />
                  <p>当前项目暂无标准客户端证书记录</p>
                </div>
              </td>
            </tr>
          </tbody>
        </table>
      </div>

      <!-- 分页控制 -->
      <div v-if="totalPages > 1" class="pagination">
        <button
          type="button"
          class="button small secondary"
          :disabled="page <= 0 || loading"
          @click="handlePageChange(page - 1)"
        >
          <ChevronLeft :size="14" /> 上一页
        </button>
        <span class="page-info">第 {{ page + 1 }} / {{ totalPages }} 页</span>
        <button
          type="button"
          class="button small secondary"
          :disabled="page >= totalPages - 1 || loading"
          @click="handlePageChange(page + 1)"
        >
          下一页 <ChevronRight :size="14" />
        </button>
      </div>
    </section>

    <!-- 吊销确认对话框 (强调：吊销≠本地解绑) -->
    <div v-if="revokingCert" class="modal-backdrop" @click.self="!revoking && (revokingCert = null)">
      <div class="modal-card" role="dialog" aria-modal="true">
        <div class="modal-header">
          <AlertTriangle :size="22" class="text-danger" />
          <h3>确认吊销客户端证书</h3>
        </div>
        <div class="modal-body">
          <p>
            您正在准备吊销设备 <strong>{{ revokingCert.deviceLabel }}</strong> 的客户端证书：
          </p>
          <div class="cert-summary mono">
            <div>序列号：{{ revokingCert.serial }}</div>
            <div>指纹：{{ revokingCert.fingerprint }}</div>
          </div>

          <!-- 极其重要的安全风险提示 -->
          <div class="warning-box">
            <strong>重要提示：吊销≠本地解绑</strong>
            <p>
              在服务端完成证书吊销后，该证书将被标记为失效并拒绝后续 mTLS 握手。
              但<strong>本操作不会自动清除或解绑客户端本地保存的私钥和证书文件</strong>（吊销 ≠ 本地解绑）。
              如需彻底停用，请同时在客户端设备或本地系统中手动解绑或清理该证书。
            </p>
          </div>

          <div v-if="revokeError" class="banner error">
            {{ revokeError }}
          </div>
        </div>
        <div class="modal-footer">
          <button
            type="button"
            class="button secondary"
            :disabled="revoking"
            @click="revokingCert = null"
          >
            取消
          </button>
          <button
            type="button"
            class="button danger"
            data-test="confirm-revoke-btn"
            :disabled="revoking"
            @click="confirmRevoke"
          >
            {{ revoking ? '正在吊销…' : '确认吊销证书' }}
          </button>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.standard-cert-manager {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.admin-banner {
  display: flex;
  justify-content: space-between;
  align-items: center;
  padding: 1rem 1.25rem;
  background: var(--surface-2, #f8fafc);
  border: 1px solid var(--border-color, #e2e8f0);
  border-radius: 8px;
}

.banner-title {
  display: flex;
  align-items: flex-start;
  gap: 0.75rem;
}

.banner-title h3 {
  margin: 0 0 0.25rem 0;
  font-size: 1.1rem;
  color: var(--text-primary, #0f172a);
}

.banner-title p {
  margin: 0;
  font-size: 0.875rem;
  color: var(--text-secondary, #64748b);
}

.copy-alert {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  padding: 0.35rem 0.75rem;
  background: #ecfdf5;
  color: #065f46;
  border-radius: 6px;
  font-size: 0.85rem;
  font-weight: 500;
}

.service-down {
  display: flex;
  align-items: center;
  justify-content: space-between;
  padding: 0.85rem 1.25rem;
  border-radius: 8px;
}

.alert-content p {
  margin: 0.25rem 0 0 0;
  font-size: 0.875rem;
}

.issue-panel,
.list-panel {
  padding: 1.25rem;
  background: #ffffff;
  border: 1px solid var(--border-color, #e2e8f0);
  border-radius: 8px;
}

.heading-with-icon {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.heading-with-icon h4 {
  margin: 0;
  font-size: 1.05rem;
}

.issue-form {
  display: flex;
  flex-direction: column;
  gap: 1rem;
  margin-top: 1rem;
}

.field {
  display: flex;
  flex-direction: column;
  gap: 0.35rem;
}

.field label {
  font-size: 0.875rem;
  font-weight: 600;
  color: var(--text-primary, #1e293b);
}

.sub-tip {
  font-weight: normal;
  color: #ef4444;
  margin-left: 0.5rem;
  font-size: 0.8rem;
}

.required {
  color: #ef4444;
}

.request-id-hint {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  font-size: 0.8rem;
  color: var(--text-secondary, #64748b);
  background: #f1f5f9;
  padding: 0.35rem 0.65rem;
  border-radius: 4px;
}

.search-box {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.search-box input {
  min-width: 260px;
  padding: 0.4rem 0.65rem;
  border: 1px solid var(--border-color, #cbd5e1);
  border-radius: 6px;
  font-size: 0.875rem;
}

.table-wrap {
  overflow-x: auto;
  margin-top: 1rem;
}

.cert-table {
  width: 100%;
  border-collapse: collapse;
  font-size: 0.875rem;
}

.cert-table th,
.cert-table td {
  padding: 0.75rem 0.65rem;
  text-align: left;
  border-bottom: 1px solid var(--border-color, #f1f5f9);
}

.cert-table th {
  background: #f8fafc;
  color: #475569;
  font-weight: 600;
}

.device-cell {
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.fingerprint-cell {
  display: flex;
  align-items: center;
  gap: 0.35rem;
}

.fp-code {
  font-size: 0.75rem;
  background: #f1f5f9;
  padding: 0.2rem 0.4rem;
  border-radius: 4px;
}

.row-actions {
  display: flex;
  gap: 0.35rem;
  align-items: center;
  flex-wrap: wrap;
}

.pagination {
  display: flex;
  align-items: center;
  justify-content: flex-end;
  gap: 0.75rem;
  margin-top: 1rem;
}

.modal-backdrop {
  position: fixed;
  inset: 0;
  background: rgba(15, 23, 42, 0.5);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 1000;
}

.modal-card {
  background: #ffffff;
  border-radius: 10px;
  width: 100%;
  max-width: 520px;
  box-shadow: 0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04);
  padding: 1.5rem;
}

.modal-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  margin-bottom: 1rem;
}

.modal-header h3 {
  margin: 0;
  font-size: 1.15rem;
}

.cert-summary {
  background: #f8fafc;
  padding: 0.65rem 0.85rem;
  border-radius: 6px;
  margin: 0.75rem 0;
  font-size: 0.8rem;
  line-height: 1.5;
}

.warning-box {
  background: #fffbeb;
  border: 1px solid #fef3c7;
  border-left: 4px solid #f59e0b;
  padding: 0.85rem;
  border-radius: 4px;
  margin: 1rem 0;
  font-size: 0.85rem;
  color: #92400e;
}

.warning-box strong {
  display: block;
  margin-bottom: 0.35rem;
  color: #b45309;
}

.warning-box p {
  margin: 0;
  line-height: 1.4;
}

.modal-footer {
  display: flex;
  justify-content: flex-end;
  gap: 0.5rem;
  margin-top: 1.25rem;
}

.text-danger {
  color: #dc2626;
}

.empty-cell {
  text-align: center;
  padding: 2.5rem 0;
}

.empty-state {
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
  color: #94a3b8;
}
</style>
