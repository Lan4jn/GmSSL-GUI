<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import {
  ShieldCheck,
  ShieldAlert,
  FileKey2,
  FileText,
  Search,
  Download,
  ChevronRight,
  ChevronDown,
  Layers,
  AlertCircle,
  Clock,
  RotateCcw,
  ArrowUpRight
} from 'lucide-vue-next'
import type {
  CertificateNode,
  CsrNode,
  BundleNode,
  CertificateTreeResponse,
  CertificateCategory,
  CertificateValidityStatus,
  CsrMatchEvidence,
  CsrMatchKind
} from '../types'
import { getProjectCertificates, download, errorMessage } from '../api'

const props = defineProps<{
  projectId: string
}>()

const loading = ref(false)
const error = ref('')
const treeData = ref<CertificateTreeResponse>({ nodes: [], csrs: [], bundles: [] })
const searchQuery = ref('')
const categoryFilter = ref<string>('ALL')
const validityFilter = ref<string>('ALL')
const selectedCaId = ref<string>('ALL')
const expandedNodeIds = ref<Set<string>>(new Set())
const highlightedCertId = ref<string>('')

function findCsrByRef(ref: string): CsrNode | undefined {
  if (!ref) return undefined
  const cleanRef = stripFilePrefix(ref)
  return (treeData.value?.csrs || []).find(c => stripFilePrefix(c.id) === cleanRef)
}

function findCertById(id: string): CertificateNode | undefined {
  if (!id) return undefined
  return (treeData.value?.nodes || []).find(n => n.id === id)
}

function formatEvidence(evidence?: CsrMatchEvidence): { text: string; css: string } | null {
  if (!evidence) return null
  switch (evidence) {
    case 'KEY_AND_SUBJECT_MATCH':
      return { text: '公钥与主体一致', css: 'badge-valid' }
    case 'KEY_MATCH_DIFFERENT_SUBJECT':
      return { text: '公钥一致 (主体不同)', css: 'badge-pending' }
    case 'AMBIGUOUS_MATCH':
      return { text: '多重匹配 (同公钥多材料)', css: 'badge-ambiguous' }
    default:
      return null
  }
}

function formatCsrMatchKind(kind?: CsrMatchKind, ambiguous?: boolean, certCount?: number): { text: string; css: string } {
  if (kind === 'INVALID_CSR') {
    return { text: 'CSR格式或签名无效', css: 'badge-expired' }
  }
  if (ambiguous) {
    if (certCount && certCount > 1) {
      return { text: '多张证书匹配（非唯一来源）', css: 'badge-ambiguous' }
    }
    return { text: '多份材料匹配（非唯一来源）', css: 'badge-ambiguous' }
  }
  switch (kind) {
    case 'KEY_AND_SUBJECT_MATCH':
      return { text: '公钥与主体一致', css: 'badge-valid' }
    case 'KEY_MATCH_DIFFERENT_SUBJECT':
      return { text: '公钥一致 (主体不同)', css: 'badge-pending' }
    case 'UNMATCHED':
      return { text: '未找到匹配证书', css: 'badge-neutral' }
    default:
      return { text: '未找到匹配证书', css: 'badge-neutral' }
  }
}

function expandAncestors(nodeId: string, visited: Set<string> = new Set()) {
  if (visited.has(nodeId)) return
  visited.add(nodeId)
  const node = (treeData.value?.nodes || []).find(n => n.id === nodeId)
  if (!node || !node.parentRefs || !node.parentRefs.length) return
  for (const pid of node.parentRefs) {
    expandedNodeIds.value.add(pid)
    expandAncestors(pid, visited)
  }
}

function locateCertificate(certId: string) {
  const targetNode = findCertById(certId)
  if (!targetNode) return

  // 若当前过滤条件隐藏了目标证书，自动清除冲突过滤项
  if (!nodeMatches(targetNode)) {
    categoryFilter.value = 'ALL'
    validityFilter.value = 'ALL'
    selectedCaId.value = 'ALL'
    searchQuery.value = ''
  }

  // 递归展开所有上级祖先节点
  expandAncestors(certId)
  if (targetNode.isCa) {
    expandedNodeIds.value.add(certId)
  }

  // 高亮目标节点
  highlightedCertId.value = certId
  setTimeout(() => {
    if (highlightedCertId.value === certId) {
      highlightedCertId.value = ''
    }
  }, 3500)

  // 平滑滚动至目标卡片
  setTimeout(() => {
    const el = document.getElementById('cert-node-' + certId)
    el?.scrollIntoView({ behavior: 'smooth', block: 'center' })
  }, 100)
}

// 所有可供筛选的 CA 列表（包含根 CA 与中间 CA，即便已过期也可作为历史筛选源）
const availableCas = computed(() =>
  (treeData.value?.nodes || []).filter(
    n => n.isCa && n.category !== 'UNSUPPORTED' && n.category !== 'ENGINE_PENDING'
  )
)

// 判断节点是否为 targetCaId 的后代（支持多父 parentRefs 且递归防环）
function isDescendantOfCa(nodeId: string, targetCaId: string, visited: Set<string> = new Set()): boolean {
  if (visited.has(nodeId)) return false
  visited.add(nodeId)
  const node = (treeData.value?.nodes || []).find(n => n.id === nodeId)
  if (!node || !node.parentRefs || !node.parentRefs.length) return false
  if (node.parentRefs.includes(targetCaId)) return true
  return node.parentRefs.some(pid => isDescendantOfCa(pid, targetCaId, new Set(visited)))
}

function matchesCaFilter(node: CertificateNode): boolean {
  if (selectedCaId.value === 'ALL') return true
  if (node.id === selectedCaId.value) return true
  if (isDescendantOfCa(node.id, selectedCaId.value)) return true
  if (isDescendantOfCa(selectedCaId.value, node.id)) return true // 保留祖先上下文
  return false
}

// 读取证书数据
async function loadCertificates() {
  if (!props.projectId) return
  loading.value = true
  error.value = ''
  try {
    const res = await getProjectCertificates(props.projectId)
    treeData.value = (res && Array.isArray(res.nodes)) ? res : { nodes: [], csrs: [], bundles: [] }
    // 默认展开所有根 CA
    for (const n of (treeData.value?.nodes || [])) {
      if (n.category === 'ROOT_CA' || n.category === 'INTERMEDIATE_CA') {
        expandedNodeIds.value.add(n.id)
      }
    }
  } catch (err) {
    error.value = errorMessage(err)
  } finally {
    loading.value = false
  }
}

watch(() => props.projectId, () => {
  expandedNodeIds.value.clear()
  selectedCaId.value = 'ALL'
  loadCertificates()
}, { immediate: true })

function toggleExpand(id: string) {
  if (expandedNodeIds.value.has(id)) {
    expandedNodeIds.value.delete(id)
  } else {
    expandedNodeIds.value.add(id)
  }
}

// 搜索与过滤
function matchesSearch(text: string): boolean {
  if (!searchQuery.value.trim()) return true
  return text.toLowerCase().includes(searchQuery.value.toLowerCase().trim())
}

function nodeMatches(node: CertificateNode): boolean {
  if (!matchesCaFilter(node)) {
    return false
  }
  if (categoryFilter.value !== 'ALL' && node.category !== categoryFilter.value) {
    return false
  }
  if (validityFilter.value !== 'ALL' && node.validityStatus !== validityFilter.value) {
    return false
  }
  return (
    matchesSearch(node.subjectCN) ||
    matchesSearch(node.name) ||
    matchesSearch(node.issuerCN) ||
    (node.serialNumber ? matchesSearch(node.serialNumber) : false)
  )
}

// 拓扑树构建逻辑（严格防止循环引用与重复节点）
const rootCaNodes = computed(() =>
  (treeData.value?.nodes || []).filter(n => n.category === 'ROOT_CA' && nodeMatches(n))
)

// 判断节点是否挂载在某个 ROOT_CA 下（防止死循环）
function isDescendantOfRoot(nodeId: string, visited: Set<string> = new Set()): boolean {
  if (visited.has(nodeId)) return false
  visited.add(nodeId)
  const node = (treeData.value?.nodes || []).find(n => n.id === nodeId)
  if (!node) return false
  if (node.category === 'ROOT_CA') return true
  if (!node.parentRefs || !node.parentRefs.length) return false
  return node.parentRefs.some(pid => isDescendantOfRoot(pid, new Set(visited)))
}

const selfSignedEndEntityNodes = computed(() =>
  (treeData.value?.nodes || []).filter(n => n.category === 'SELF_SIGNED_END_ENTITY' && nodeMatches(n))
)

// 孤立证书包含：明确标记 ORPHAN 的证书，以及未挂载在任何 ROOT_CA 下的非终端自签证书（如循环引用节点）
const orphanNodes = computed(() =>
  (treeData.value?.nodes || []).filter(n => {
    if (n.category === 'SELF_SIGNED_END_ENTITY' || n.category === 'UNSUPPORTED' || n.category === 'ENGINE_PENDING') return false
    if (n.category === 'ORPHAN') return nodeMatches(n)
    if (n.category !== 'ROOT_CA' && !isDescendantOfRoot(n.id)) return nodeMatches(n)
    return false
  })
)

const unsupportedNodes = computed(() =>
  (treeData.value?.nodes || []).filter(n => (n.category === 'UNSUPPORTED' || n.category === 'ENGINE_PENDING') && nodeMatches(n))
)

const filteredCsrs = computed(() => {
  if (selectedCaId.value !== 'ALL') return [] // 筛选特定 CA 时，独立未签发 CSR 不属于该 CA 后代
  return (treeData.value?.csrs || []).filter(c => matchesSearch(c.subjectCN) || matchesSearch(c.name))
})

const filteredBundles = computed(() => {
  return (treeData.value?.bundles || []).filter(b => {
    if (!matchesSearch(b.name)) return false
    if (selectedCaId.value === 'ALL') return true
    return (b.containsCertIds || []).some(cid => {
      const n = (treeData.value?.nodes || []).find(x => x.id === cid)
      return n ? matchesCaFilter(n) : false
    })
  })
})

// 查找直属子证书（支持多父 parentRefs，带 visited 集合防止环路）
function getChildNodes(parentId: string, visited: Set<string> = new Set()): CertificateNode[] {
  if (visited.has(parentId)) return []
  const currentVisited = new Set(visited).add(parentId)

  return (treeData.value?.nodes || []).filter(n => {
    if (!n.parentRefs || !n.parentRefs.includes(parentId)) return false
    // 递归检查避免直系循环
    if (currentVisited.has(n.id)) return false
    return nodeMatches(n)
  })
}

// 下载处理 (严格区分单文件 downloadRef 与 bundle 文件，绝不能以 cert:<fingerprint> 请求后端)
function stripFilePrefix(ref?: string): string | null {
  if (!ref) return null
  return ref.startsWith('file:') ? ref.slice(5) : ref
}

async function handleDownloadCert(node: CertificateNode) {
  const fileTarget = stripFilePrefix(node.downloadRef || node.sourceFileRef)
  if (!fileTarget) {
    alert('该证书仅包含于证书链合辑 (Bundle) 中，无独立单证书文件。请在下方证书链区下载原合辑。')
    return
  }
  await download(`/projects/${props.projectId}/files/${fileTarget}/download`, node.name)
}

async function handleDownloadCsr(csr: CsrNode) {
  const fileTarget = stripFilePrefix(csr.downloadRef || csr.id)
  if (!fileTarget) return
  await download(`/projects/${props.projectId}/files/${fileTarget}/download`, csr.name)
}

async function handleDownloadBundle(bundle: BundleNode) {
  const fileTarget = stripFilePrefix(bundle.downloadRef || bundle.id)
  if (!fileTarget) return
  await download(`/projects/${props.projectId}/files/${fileTarget}/download`, bundle.name)
}

function formatValidity(status: CertificateValidityStatus): { text: string; css: string } {
  if (status === 'VALID') return { text: '有效', css: 'badge-valid' }
  if (status === 'EXPIRED') return { text: '已过期', css: 'badge-expired' }
  if (status === 'NOT_YET_VALID') return { text: '未生效', css: 'badge-pending' }
  return { text: '未识别/未知', css: 'badge-pending' }
}

function formatCategory(category: CertificateCategory): string {
  switch (category) {
    case 'ROOT_CA': return '根 CA'
    case 'INTERMEDIATE_CA': return '中间 CA'
    case 'ISSUED_CERT': return '终端证书'
    case 'SELF_SIGNED_END_ENTITY': return '自签名服务证书'
    case 'ORPHAN': return '缺失上级'
    case 'UNSUPPORTED': return '格式不支持'
    case 'ENGINE_PENDING': return '待引擎解析'
    default: return category
  }
}
</script>

<template>
  <div class="certificate-tree-container">
    <!-- 顶部工具条：搜索、分类筛选、刷新 -->
    <div class="tree-toolbar">
      <div class="search-box">
        <Search :size="16" />
        <input
          v-model="searchQuery"
          type="text"
          class="tree-search-input"
          placeholder="搜索证书主体 CN、文件名、序列号或签发者…"
          spellcheck="false"
        />
      </div>

      <div class="filter-actions">
        <select v-model="selectedCaId" class="filter-select ca-select" aria-label="签发 CA 过滤">
          <option value="ALL">全部签发 CA</option>
          <option v-for="ca in availableCas" :key="ca.id" :value="ca.id">
            {{ ca.subjectCN }} ({{ ca.name }}{{ ca.serialNumber ? ' · SN:' + ca.serialNumber.slice(-8) : '' }}{{ ca.validityStatus === 'EXPIRED' ? ' · 已过期' : '' }})
          </option>
        </select>

        <select v-model="categoryFilter" class="filter-select type-select" aria-label="证书分类过滤">
          <option value="ALL">全部证书类型</option>
          <option value="ROOT_CA">仅看根 CA</option>
          <option value="INTERMEDIATE_CA">仅看中间 CA</option>
          <option value="ISSUED_CERT">由 CA 签发的证书</option>
          <option value="SELF_SIGNED_END_ENTITY">自签名服务证书</option>
          <option value="ORPHAN">缺失上级 CA 证书</option>
        </select>

        <select v-model="validityFilter" class="filter-select validity-select" aria-label="有效期过滤">
          <option value="ALL">全部有效期状态</option>
          <option value="VALID">仅有效</option>
          <option value="EXPIRED">已过期</option>
          <option value="NOT_YET_VALID">未生效</option>
        </select>

        <button type="button" class="button small secondary" :disabled="loading" @click="loadCertificates">
          <RotateCcw :size="14" :class="{ 'spinning': loading }" />
          <span>刷新</span>
        </button>
      </div>
    </div>

    <!-- 错误横幅 -->
    <div v-if="error" class="banner error">
      <AlertCircle :size="16" />
      <span>证书库拓扑加载异常: {{ error }}</span>
    </div>

    <!-- 加载指示器 -->
    <div v-if="loading" class="loading-state">
      <span>正在构建项目证书 CA 信任拓扑树…</span>
    </div>

    <!-- 主展示区 -->
    <div v-else class="tree-content">
      <!-- 1. CA 信任链树形列表 (根 CA 及下属证书) -->
      <section v-if="rootCaNodes.length" class="tree-section">
        <div class="section-header">
          <ShieldCheck :size="18" class="text-teal" />
          <h3>根 CA 与证书拓扑树</h3>
          <span class="count-badge">{{ rootCaNodes.length }} 个信任根</span>
        </div>

        <div class="roots-tree-list">
          <div v-for="rootNode in rootCaNodes" :key="rootNode.id" class="tree-branch">
            <!-- 根节点条目 -->
            <div :id="'cert-node-' + rootNode.id" class="cert-node-card root-card" :class="{ 'highlight-pulse': highlightedCertId === rootNode.id }">
              <button
                type="button"
                class="icon-button expand-toggle"
                :aria-label="expandedNodeIds.has(rootNode.id) ? '折叠' : '展开'"
                @click="toggleExpand(rootNode.id)"
              >
                <ChevronDown v-if="expandedNodeIds.has(rootNode.id)" :size="16" />
                <ChevronRight v-else :size="16" />
              </button>

              <div class="cert-icon-col">
                <FileKey2 :size="20" class="text-teal" />
              </div>

              <div class="cert-main-info">
                <div class="name-line">
                  <strong class="subject-cn">{{ rootNode.subjectCN }}</strong>
                  <span class="category-tag tag-root">{{ formatCategory(rootNode.category) }}</span>
                  <span class="badge" :class="formatValidity(rootNode.validityStatus).css">
                    {{ formatValidity(rootNode.validityStatus).text }}
                  </span>
                  <span v-if="rootNode.selectableAsIssuer" class="badge tag-issuer">可签发</span>
                  <span v-else-if="rootNode.validityStatus === 'EXPIRED'" class="badge tag-expired-issuer">已过期不可签发</span>
                </div>
                <div class="meta-line">
                  <span class="file-name mono">{{ rootNode.name }}</span>
                  <span v-if="rootNode.serialNumber" class="serial-num">序列号: {{ rootNode.serialNumber }}</span>
                  <span v-if="rootNode.validAfter" class="valid-time">到期时间: {{ new Date(rootNode.validAfter).toLocaleDateString() }}</span>
                </div>
                <!-- 关联 CSR 信息与直接下载 -->
                <div v-if="rootNode.matchedCsrRefs && rootNode.matchedCsrRefs.length" class="matched-csr-box">
                  <span class="csr-link-label">
                    <FileText :size="12" />
                    <span>关联 CSR:</span>
                  </span>
                  <span v-for="csrRef in rootNode.matchedCsrRefs" :key="csrRef" class="csr-pill">
                    <span class="mono">{{ findCsrByRef(csrRef)?.name || csrRef }}</span>
                    <span v-if="rootNode.csrMatchEvidence" class="badge mini" :class="formatEvidence(rootNode.csrMatchEvidence)?.css">
                      {{ formatEvidence(rootNode.csrMatchEvidence)?.text }}
                    </span>
                    <button
                      v-if="findCsrByRef(csrRef)"
                      type="button"
                      class="icon-button mini-btn"
                      :aria-label="'下载关联 CSR ' + findCsrByRef(csrRef)!.name"
                      title="下载关联 CSR"
                      @click="handleDownloadCsr(findCsrByRef(csrRef)!)"
                    >
                      <Download :size="12" />
                    </button>
                  </span>
                </div>
              </div>

              <div class="cert-actions">
                <button
                  type="button"
                  class="button small secondary download-btn"
                  :aria-label="'下载证书 ' + rootNode.name"
                  @click="handleDownloadCert(rootNode)"
                >
                  <Download :size="14" />
                  <span>下载</span>
                </button>
              </div>
            </div>

            <!-- 子证书递归展开区 -->
            <div v-if="expandedNodeIds.has(rootNode.id)" class="tree-children">
              <div v-for="child in getChildNodes(rootNode.id)" :key="child.id" class="child-node-wrapper">
                <div class="tree-line-indicator" />
                <div :id="'cert-node-' + child.id" class="cert-node-card child-card" :class="{ 'highlight-pulse': highlightedCertId === child.id }">
                  <div class="cert-icon-col">
                    <FileText :size="16" class="text-slate" />
                  </div>
                  <div class="cert-main-info">
                    <div class="name-line">
                      <strong class="subject-cn">{{ child.subjectCN }}</strong>
                      <span class="category-tag">{{ formatCategory(child.category) }}</span>
                      <span class="badge" :class="formatValidity(child.validityStatus).css">
                        {{ formatValidity(child.validityStatus).text }}
                      </span>
                    </div>
                    <div class="meta-line">
                      <span class="file-name mono">{{ child.name }}</span>
                      <span v-if="child.serialNumber" class="serial-num">SN: {{ child.serialNumber }}</span>
                      <span v-if="child.validAfter" class="valid-time">有效至: {{ new Date(child.validAfter).toLocaleDateString() }}</span>
                    </div>
                    <!-- 关联 CSR 信息与直接下载 -->
                    <div v-if="child.matchedCsrRefs && child.matchedCsrRefs.length" class="matched-csr-box">
                      <span class="csr-link-label">
                        <FileText :size="12" />
                        <span>关联 CSR:</span>
                      </span>
                      <span v-for="csrRef in child.matchedCsrRefs" :key="csrRef" class="csr-pill">
                        <span class="mono">{{ findCsrByRef(csrRef)?.name || csrRef }}</span>
                        <span v-if="child.csrMatchEvidence" class="badge mini" :class="formatEvidence(child.csrMatchEvidence)?.css">
                          {{ formatEvidence(child.csrMatchEvidence)?.text }}
                        </span>
                        <button
                          v-if="findCsrByRef(csrRef)"
                          type="button"
                          class="icon-button mini-btn"
                          :aria-label="'下载关联 CSR ' + findCsrByRef(csrRef)!.name"
                          title="下载关联 CSR"
                          @click="handleDownloadCsr(findCsrByRef(csrRef)!)"
                        >
                          <Download :size="12" />
                        </button>
                      </span>
                    </div>
                  </div>
                  <div class="cert-actions">
                    <button
                      type="button"
                      class="button small secondary download-btn"
                      :aria-label="'下载证书 ' + child.name"
                      @click="handleDownloadCert(child)"
                    >
                      <Download :size="14" />
                      <span>下载</span>
                    </button>
                  </div>
                </div>

                <!-- 二级中间 CA 递归展开 -->
                <div v-if="child.isCa && expandedNodeIds.has(child.id)" class="tree-children sub-children">
                  <div v-for="grandChild in getChildNodes(child.id)" :key="grandChild.id" class="child-node-wrapper">
                    <div class="tree-line-indicator" />
                    <div :id="'cert-node-' + grandChild.id" class="cert-node-card child-card" :class="{ 'highlight-pulse': highlightedCertId === grandChild.id }">
                      <div class="cert-icon-col">
                        <FileText :size="16" />
                      </div>
                      <div class="cert-main-info">
                        <div class="name-line">
                          <strong class="subject-cn">{{ grandChild.subjectCN }}</strong>
                          <span class="category-tag">{{ formatCategory(grandChild.category) }}</span>
                        </div>
                        <div class="meta-line">
                          <span class="file-name mono">{{ grandChild.name }}</span>
                        </div>
                        <!-- 关联 CSR 信息与直接下载 -->
                        <div v-if="grandChild.matchedCsrRefs && grandChild.matchedCsrRefs.length" class="matched-csr-box">
                          <span class="csr-link-label">
                            <FileText :size="12" />
                            <span>关联 CSR:</span>
                          </span>
                          <span v-for="csrRef in grandChild.matchedCsrRefs" :key="csrRef" class="csr-pill">
                            <span class="mono">{{ findCsrByRef(csrRef)?.name || csrRef }}</span>
                            <span v-if="grandChild.csrMatchEvidence" class="badge mini" :class="formatEvidence(grandChild.csrMatchEvidence)?.css">
                              {{ formatEvidence(grandChild.csrMatchEvidence)?.text }}
                            </span>
                            <button
                              v-if="findCsrByRef(csrRef)"
                              type="button"
                              class="icon-button mini-btn"
                              :aria-label="'下载关联 CSR ' + findCsrByRef(csrRef)!.name"
                              title="下载关联 CSR"
                              @click="handleDownloadCsr(findCsrByRef(csrRef)!)"
                            >
                              <Download :size="12" />
                            </button>
                          </span>
                        </div>
                      </div>
                      <div class="cert-actions">
                        <button
                          type="button"
                          class="button small secondary download-btn"
                          :aria-label="'下载证书 ' + grandChild.name"
                          @click="handleDownloadCert(grandChild)"
                        >
                          <Download :size="14" />
                          <span>下载</span>
                        </button>
                      </div>
                    </div>
                  </div>
                </div>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- 2. 自签名终端服务证书 (CA=false) 独立分组 -->
      <section v-if="selfSignedEndEntityNodes.length" class="tree-section">
        <div class="section-header">
          <Clock :size="18" class="text-blue" />
          <h3>自签名终端服务证书</h3>
          <span class="count-badge">{{ selfSignedEndEntityNodes.length }}</span>
        </div>
        <p class="section-hint">单向点对点或测试使用的端实体自签证书（CA=false），不可作为 CA 签发下级证书。</p>

        <div class="flat-certs-list">
          <div :id="'cert-node-' + node.id" v-for="node in selfSignedEndEntityNodes" :key="node.id" class="cert-node-card flat-card" :class="{ 'highlight-pulse': highlightedCertId === node.id }">
            <div class="cert-icon-col">
              <FileKey2 :size="18" class="text-blue" />
            </div>
            <div class="cert-main-info">
              <div class="name-line">
                <strong class="subject-cn">{{ node.subjectCN }}</strong>
                <span class="badge" :class="formatValidity(node.validityStatus).css">
                  {{ formatValidity(node.validityStatus).text }}
                </span>
              </div>
              <div class="meta-line">
                <span class="file-name mono">{{ node.name }}</span>
                <span v-if="node.validAfter">有效至: {{ new Date(node.validAfter).toLocaleDateString() }}</span>
              </div>
              <!-- 关联 CSR 信息与直接下载 -->
              <div v-if="node.matchedCsrRefs && node.matchedCsrRefs.length" class="matched-csr-box">
                <span class="csr-link-label">
                  <FileText :size="12" />
                  <span>关联 CSR:</span>
                </span>
                <span v-for="csrRef in node.matchedCsrRefs" :key="csrRef" class="csr-pill">
                  <span class="mono">{{ findCsrByRef(csrRef)?.name || csrRef }}</span>
                  <span v-if="node.csrMatchEvidence" class="badge mini" :class="formatEvidence(node.csrMatchEvidence)?.css">
                    {{ formatEvidence(node.csrMatchEvidence)?.text }}
                  </span>
                  <button
                    v-if="findCsrByRef(csrRef)"
                    type="button"
                    class="icon-button mini-btn"
                    :aria-label="'下载关联 CSR ' + findCsrByRef(csrRef)!.name"
                    title="下载关联 CSR"
                    @click="handleDownloadCsr(findCsrByRef(csrRef)!)"
                  >
                    <Download :size="12" />
                  </button>
                </span>
              </div>
            </div>
            <div class="cert-actions">
              <button
                type="button"
                class="button small secondary download-btn"
                :aria-label="'下载证书 ' + node.name"
                @click="handleDownloadCert(node)"
              >
                <Download :size="14" />
                <span>下载</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- 3. 缺失上级 CA 或外部导入证书 (ORPHAN) -->
      <section v-if="orphanNodes.length" class="tree-section">
        <div class="section-header">
          <ShieldAlert :size="18" class="text-amber" />
          <h3>外部或缺失上级 CA 的证书</h3>
          <span class="count-badge">{{ orphanNodes.length }}</span>
        </div>
        <p class="section-hint">由外部权威签发或本项目中未找到其对应签发 CA 证书的文件。</p>

        <div class="flat-certs-list">
          <div :id="'cert-node-' + node.id" v-for="node in orphanNodes" :key="node.id" class="cert-node-card flat-card orphan-card" :class="{ 'highlight-pulse': highlightedCertId === node.id }">
            <div class="cert-icon-col">
              <FileText :size="18" class="text-amber" />
            </div>
            <div class="cert-main-info">
              <div class="name-line">
                <strong class="subject-cn">{{ node.subjectCN }}</strong>
                <span class="category-tag tag-orphan">签发者: {{ node.issuerCN || '未指定' }}</span>
              </div>
              <div class="meta-line">
                <span class="file-name mono">{{ node.name }}</span>
              </div>
              <!-- 关联 CSR 信息与直接下载 -->
              <div v-if="node.matchedCsrRefs && node.matchedCsrRefs.length" class="matched-csr-box">
                <span class="csr-link-label">
                  <FileText :size="12" />
                  <span>关联 CSR:</span>
                </span>
                <span v-for="csrRef in node.matchedCsrRefs" :key="csrRef" class="csr-pill">
                  <span class="mono">{{ findCsrByRef(csrRef)?.name || csrRef }}</span>
                  <span v-if="node.csrMatchEvidence" class="badge mini" :class="formatEvidence(node.csrMatchEvidence)?.css">
                    {{ formatEvidence(node.csrMatchEvidence)?.text }}
                  </span>
                  <button
                    v-if="findCsrByRef(csrRef)"
                    type="button"
                    class="icon-button mini-btn"
                    :aria-label="'下载关联 CSR ' + findCsrByRef(csrRef)!.name"
                    title="下载关联 CSR"
                    @click="handleDownloadCsr(findCsrByRef(csrRef)!)"
                  >
                    <Download :size="12" />
                  </button>
                </span>
              </div>
            </div>
            <div class="cert-actions">
              <button
                type="button"
                class="button small secondary download-btn"
                :aria-label="'下载证书 ' + node.name"
                @click="handleDownloadCert(node)"
              >
                <Download :size="14" />
                <span>下载</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- 4. 证书签名申请 (CSR) 独立分组 -->
      <section v-if="filteredCsrs.length" class="tree-section">
        <div class="section-header">
          <FileText :size="18" class="text-purple" />
          <h3>证书申请文件 (CSR)</h3>
          <span class="count-badge">{{ filteredCsrs.length }}</span>
        </div>

        <div class="flat-certs-list">
          <div v-for="csr in filteredCsrs" :key="csr.id" class="cert-node-card flat-card csr-card">
            <div class="cert-icon-col">
              <FileText :size="18" class="text-purple" />
            </div>
            <div class="cert-main-info">
              <div class="name-line">
                <strong class="subject-cn">{{ csr.subjectCN || csr.name }}</strong>
                <span class="category-tag">PKCS#10 申请</span>
                <span class="badge" :class="formatCsrMatchKind(csr.matchKind, csr.ambiguous, csr.matchedCertIds?.length).css">
                  {{ formatCsrMatchKind(csr.matchKind, csr.ambiguous, csr.matchedCertIds?.length).text }}
                </span>
              </div>
              <div class="meta-line">
                <span class="file-name mono">{{ csr.name }}</span>
                <span v-if="csr.createdAt">创建于: {{ new Date(csr.createdAt).toLocaleDateString() }}</span>
              </div>

              <!-- 坏 CSR 明确设置错误提示 -->
              <div v-if="csr.error" class="csr-error-line text-danger" style="font-size:0.8rem;margin-top:0.3rem;display:flex;align-items:center;gap:0.35rem;color:#b91c1c;">
                <AlertCircle :size="14" />
                <span>{{ csr.error }}</span>
              </div>

              <!-- 反向关联证书列表与定位按钮 -->
              <div v-if="csr.matchedCertIds && csr.matchedCertIds.length" class="csr-matched-certs">
                <span class="matched-cert-label">对应证书:</span>
                <span v-for="certId in csr.matchedCertIds" :key="certId" class="cert-link-chip">
                  <span class="mono">{{ findCertById(certId)?.name || certId }}</span>
                  <button
                    type="button"
                    class="text-button small locate-btn"
                    :aria-label="'在树中定位证书 ' + (findCertById(certId)?.name || certId)"
                    title="在 CA 信任树中展开并定位此证书"
                    @click="locateCertificate(certId)"
                  >
                    <ArrowUpRight :size="12" />
                    <span>定位</span>
                  </button>
                </span>
              </div>
            </div>
            <div class="cert-actions">
              <button
                type="button"
                class="button small secondary download-btn"
                :aria-label="'下载 CSR ' + csr.name"
                @click="handleDownloadCsr(csr)"
              >
                <Download :size="14" />
                <span>下载</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- 5. 完整证书链 (Bundle) 独立展示 -->
      <section v-if="filteredBundles.length" class="tree-section">
        <div class="section-header">
          <Layers :size="18" class="text-blue" />
          <h3>证书链文件 (Bundle)</h3>
          <span class="count-badge">{{ filteredBundles.length }}</span>
        </div>

        <div class="flat-certs-list">
          <div v-for="bundle in filteredBundles" :key="bundle.id" class="cert-node-card flat-card">
            <div class="cert-icon-col">
              <Layers :size="18" class="text-blue" />
            </div>
            <div class="cert-main-info">
              <div class="name-line">
                <strong class="subject-cn">{{ bundle.name }}</strong>
                <span class="category-tag">含 {{ bundle.containsCertIds.length }} 级证书</span>
              </div>
              <div class="meta-line">
                <span class="hint">可直接部署于 Nginx、Apache、TLS/TLCP 服务端</span>
              </div>
            </div>
            <div class="cert-actions">
              <button
                type="button"
                class="button small secondary download-btn"
                :aria-label="'下载证书链 ' + bundle.name"
                @click="handleDownloadBundle(bundle)"
              >
                <Download :size="14" />
                <span>下载</span>
              </button>
            </div>
          </div>
        </div>
      </section>

      <!-- 6. 异常或格式不支持的材料 (UNSUPPORTED / ENGINE_PENDING) -->
      <section v-if="unsupportedNodes.length" class="tree-section">
        <div class="section-header">
          <AlertCircle :size="18" class="text-amber" />
          <h3>待解析或格式不支持材料</h3>
          <span class="count-badge">{{ unsupportedNodes.length }}</span>
        </div>
        <p class="section-hint">文件可能包含非标准编码、损坏的 X.509 结构或正在等待原生引擎深度分析。</p>

        <div class="flat-certs-list">
          <div v-for="node in unsupportedNodes" :key="node.id" class="cert-node-card flat-card">
            <div class="cert-icon-col">
              <AlertCircle :size="18" class="text-amber" />
            </div>
            <div class="cert-main-info">
              <div class="name-line">
                <strong class="subject-cn">{{ node.name }}</strong>
                <span class="category-tag tag-orphan">{{ formatCategory(node.category) }}</span>
                <span v-if="node.error" class="badge badge-expired">{{ node.error }}</span>
              </div>
              <div class="meta-line">
                <span class="file-name mono">{{ node.id }}</span>
              </div>
            </div>
          </div>
        </div>
      </section>

      <!-- 空状态 -->
      <div v-if="!treeData.nodes.length && !treeData.csrs.length && !treeData.bundles.length" class="empty-tree">
        <FileKey2 :size="40" class="text-slate" />
        <p>当前项目尚未保存任何证书、CA 或 CSR 材料。</p>
        <small class="muted">可通过上方证书向导快速制作自签名证书或创建根 CA。</small>
      </div>
    </div>
  </div>
</template>

<style scoped>
.certificate-tree-container {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
}

.tree-toolbar {
  display: flex;
  align-items: center;
  justify-content: space-between;
  gap: 1rem;
  background: #ffffff;
  padding: 0.75rem 1rem;
  border: 1px solid #e2e8f0;
  border-radius: 8px;
}

.search-box {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-grow: 1;
  max-width: 480px;
  background: #f8fafc;
  border: 1px solid #cbd5e1;
  padding: 0.35rem 0.75rem;
  border-radius: 6px;
}

.tree-search-input {
  border: none;
  background: transparent;
  width: 100%;
  font-size: 0.875rem;
  outline: none;
}

.filter-actions {
  display: flex;
  align-items: center;
  gap: 0.75rem;
}

.filter-select,
.category-select {
  padding: 0.35rem 0.75rem;
  font-size: 0.85rem;
  border: 1px solid #cbd5e1;
  border-radius: 6px;
  background: #ffffff;
}

.tree-content {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.tree-section {
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 1.25rem;
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.section-header {
  display: flex;
  align-items: center;
  gap: 0.5rem;
}

.section-header h3 {
  font-size: 1rem;
  color: #1e293b;
  margin: 0;
}

.count-badge {
  font-size: 0.75rem;
  background: #f1f5f9;
  color: #475569;
  padding: 0.1rem 0.5rem;
  border-radius: 9999px;
  margin-left: auto;
}

.section-hint {
  font-size: 0.8rem;
  color: #64748b;
  margin: 0;
}

/* 树分支与层级卡片 */
.roots-tree-list {
  display: flex;
  flex-direction: column;
  gap: 0.75rem;
}

.tree-branch {
  display: flex;
  flex-direction: column;
}

.cert-node-card {
  display: flex;
  align-items: center;
  gap: 0.75rem;
  padding: 0.75rem 1rem;
  border-radius: 8px;
  border: 1px solid #e2e8f0;
  background: #ffffff;
}

.root-card {
  background: #f0fdfa;
  border-color: #99f6e4;
}

.child-card {
  background: #ffffff;
  border-color: #e2e8f0;
}

.tree-children {
  display: flex;
  flex-direction: column;
  margin-left: 1.5rem;
  padding-left: 1rem;
  border-left: 2px dashed #cbd5e1;
  margin-top: 0.5rem;
  gap: 0.5rem;
}

.child-node-wrapper {
  position: relative;
}

.expand-toggle {
  background: transparent;
  border: none;
  cursor: pointer;
  padding: 0.2rem;
  display: flex;
  align-items: center;
  color: #0f766e;
}

.cert-main-info {
  flex-grow: 1;
  display: flex;
  flex-direction: column;
  gap: 0.2rem;
}

.name-line {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
}

.subject-cn {
  font-size: 0.95rem;
  color: #0f172a;
}

.category-tag {
  font-size: 0.75rem;
  background: #f1f5f9;
  color: #475569;
  padding: 0.1rem 0.4rem;
  border-radius: 4px;
}

.tag-root {
  background: #ccfbf1;
  color: #0f766e;
  font-weight: 600;
}

.tag-issuer {
  background: #dcfce7;
  color: #166534;
}

.tag-expired-issuer {
  background: #fee2e2;
  color: #991b1b;
}

.tag-orphan {
  background: #fef3c7;
  color: #92400e;
}

.meta-line {
  display: flex;
  align-items: center;
  gap: 1rem;
  font-size: 0.75rem;
  color: #64748b;
}

.file-name {
  color: #334155;
  font-weight: 500;
}

.badge-valid {
  background: #dcfce7;
  color: #15803d;
}

.badge-expired {
  background: #fee2e2;
  color: #b91c1c;
}

.badge-pending {
  background: #fef3c7;
  color: #b45309;
}

.flat-certs-list {
  display: flex;
  flex-direction: column;
  gap: 0.5rem;
}

.empty-tree {
  text-align: center;
  padding: 3rem 1rem;
  color: #64748b;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 0.5rem;
}

.text-teal { color: #0d9488; }
.text-blue { color: #0284c7; }
.text-amber { color: #d97706; }
.text-purple { color: #7c3aed; }
.text-slate { color: #64748b; }

.spinning {
  animation: spin 1s linear infinite;
}

@keyframes spin {
  from { transform: rotate(0deg); }
  to { transform: rotate(360deg); }
}

.matched-csr-box {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  flex-wrap: wrap;
  margin-top: 0.35rem;
  padding-top: 0.35rem;
  border-top: 1px dashed #e2e8f0;
}

.csr-link-label {
  display: inline-flex;
  align-items: center;
  gap: 0.25rem;
  font-size: 0.75rem;
  font-weight: 600;
  color: #6d28d9;
}

.csr-pill {
  display: inline-flex;
  align-items: center;
  gap: 0.35rem;
  background: #f5f3ff;
  border: 1px solid #ddd6fe;
  padding: 0.15rem 0.5rem;
  border-radius: 4px;
  font-size: 0.75rem;
  color: #5b21b6;
}

.mini-btn {
  padding: 0.1rem;
  color: #6d28d9;
  background: transparent;
  border: none;
  cursor: pointer;
  display: inline-flex;
  align-items: center;
}

.csr-matched-certs {
  display: flex;
  align-items: center;
  gap: 0.4rem;
  flex-wrap: wrap;
  margin-top: 0.35rem;
}

.matched-cert-label {
  font-size: 0.75rem;
  font-weight: 600;
  color: #0369a1;
}

.cert-link-chip {
  display: inline-flex;
  align-items: center;
  gap: 0.3rem;
  background: #f0f9ff;
  border: 1px solid #bae6fd;
  padding: 0.15rem 0.45rem;
  border-radius: 4px;
  font-size: 0.75rem;
  color: #0369a1;
}

.locate-btn {
  display: inline-flex;
  align-items: center;
  gap: 0.15rem;
  padding: 0 0.2rem;
  color: #0284c7;
}

.badge-ambiguous {
  background: #f3e8ff;
  color: #7e22ce;
}

.badge.mini {
  font-size: 0.7rem;
  padding: 0.05rem 0.35rem;
}

.highlight-pulse {
  animation: highlightPulse 2s ease infinite;
  border-color: #0284c7 !important;
  box-shadow: 0 0 0 3px rgba(2, 132, 199, 0.25) !important;
}

@keyframes highlightPulse {
  0% { box-shadow: 0 0 0 0 rgba(2, 132, 199, 0.4); }
  70% { box-shadow: 0 0 0 8px rgba(2, 132, 199, 0); }
  100% { box-shadow: 0 0 0 0 rgba(2, 132, 199, 0); }
}
</style>
