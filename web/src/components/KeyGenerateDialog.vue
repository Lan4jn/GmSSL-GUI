<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import type { Parameter, GenerateKeyRequest, GenerateKeyResponse, KeyGenerationCapabilities, GenerationProvider } from '../types'
import { generateKey, getKeyGenCapabilities, errorMessage } from '../api'
import { getAllowedAlgorithmIds } from '../forms'

const props = defineProps<{
  visible: boolean
  projectId: string
  targetParameter?: Parameter
  toolId?: string
  defaultStorage?: 'MANAGED' | 'TEMPORARY'
}>()

const emit = defineEmits<{
  'update:visible': [boolean]
  'generated': [GenerateKeyResponse]
}>()

export interface AlgorithmOption {
  id: string
  name: string
  kind: 'SYMMETRIC' | 'ASYMMETRIC'
  capabilityId: string
  payloadAlgorithm: string
  payloadCurve?: string
  defaultBits?: number
}

const ALL_ALGORITHMS: AlgorithmOption[] = [
  { id: 'SM4', name: 'SM4 (国密分组 128 位)', kind: 'SYMMETRIC', capabilityId: 'SM4', payloadAlgorithm: 'SM4', defaultBits: 128 },
  { id: 'SM4-XTS', name: 'SM4-XTS (国密 XTS 256 位)', kind: 'SYMMETRIC', capabilityId: 'SM4-XTS', payloadAlgorithm: 'SM4-XTS', defaultBits: 256 },
  { id: 'AES', name: 'AES (国际分组 128/192/256 位)', kind: 'SYMMETRIC', capabilityId: 'AES', payloadAlgorithm: 'AES', defaultBits: 128 },
  { id: 'ZUC', name: 'ZUC (祖冲之序列密码 128 位)', kind: 'SYMMETRIC', capabilityId: 'ZUC', payloadAlgorithm: 'ZUC', defaultBits: 128 },
  { id: 'ZUC256', name: 'ZUC-256 (祖冲之序列密码 256 位)', kind: 'SYMMETRIC', capabilityId: 'ZUC256', payloadAlgorithm: 'ZUC256', defaultBits: 256 },
  { id: 'HMAC', name: 'HMAC (消息认证码 256 位)', kind: 'SYMMETRIC', capabilityId: 'HMAC', payloadAlgorithm: 'HMAC', defaultBits: 256 },
  { id: 'SM2', name: 'SM2 (国密椭圆曲线密钥对)', kind: 'ASYMMETRIC', capabilityId: 'SM2', payloadAlgorithm: 'SM2', payloadCurve: 'sm2' },
  { id: 'P-256', name: 'NIST P-256 / secp256r1 密钥对', kind: 'ASYMMETRIC', capabilityId: 'EC', payloadAlgorithm: 'EC', payloadCurve: 'secp256r1' },
  { id: 'P-384', name: 'NIST P-384 / secp384r1 密钥对', kind: 'ASYMMETRIC', capabilityId: 'EC', payloadAlgorithm: 'EC', payloadCurve: 'secp384r1' }
]

const loading = ref(false)
const loadingCapabilities = ref(false)
const capabilitiesError = ref('')
const error = ref('')
const capabilities = ref<KeyGenerationCapabilities | null>(null)

const provider = ref<'gmssl' | 'openssl'>('gmssl')
const storage = ref<'MANAGED' | 'TEMPORARY'>('MANAGED')
const selectedAlgoId = ref('SM4')
const aesBits = ref(128)
const name = ref('')
const password = ref('')

const availableProviders = computed<GenerationProvider[]>(() => {
  return capabilities.value?.providers ?? []
})

const currentProviderObj = computed(() => {
  return availableProviders.value.find(p => p.id === provider.value)
})

const currentProviderAvailable = computed(() => {
  return currentProviderObj.value?.available === true
})

const availableAlgorithms = computed<AlgorithmOption[]>(() => {
  if (!currentProviderAvailable.value || !capabilities.value?.algorithms?.length) return []

  const allowedIds = getAllowedAlgorithmIds(props.toolId, props.targetParameter)

  return ALL_ALGORITHMS.filter(opt => {
    // 1. Tool / parameter exact whitelist filter
    if (allowedIds !== null && !allowedIds.includes(opt.id)) {
      return false
    }

    // 2. Context filter by target parameter type
    if (props.targetParameter?.type === 'HEX' && opt.kind !== 'SYMMETRIC') {
      return false
    }
    if (props.targetParameter?.type === 'INPUT_FILE' && opt.kind !== 'ASYMMETRIC') {
      return false
    }

    // 3. Capability existence filter
    const cap = capabilities.value?.algorithms.find(
      a => a.id.toLowerCase() === opt.capabilityId.toLowerCase()
    )
    if (!cap) return false

    // 4. Provider support filter
    if (!cap.providers?.includes(provider.value)) return false

    // 5. Curve support filter for EC
    if (opt.payloadCurve && cap.curves?.length) {
      const targetCurve = opt.payloadCurve.toLowerCase()
      const hasCurve = cap.curves.some(c => {
        const cl = c.toLowerCase()
        return cl === targetCurve || (targetCurve === 'secp256r1' && cl === 'prime256v1') || (targetCurve === 'sm2' && cl.startsWith('sm2'))
      })
      if (!hasCurve) return false
    }

    return true
  })
})

const currentSelectedAlgo = computed(() => {
  return availableAlgorithms.value.find(a => a.id === selectedAlgoId.value)
})

const isAsymmetric = computed(() => {
  return currentSelectedAlgo.value?.kind === 'ASYMMETRIC'
})

function inferInitialAlgoId(): string {
  return getAllowedAlgorithmIds(props.toolId, props.targetParameter)?.[0] ?? 'SM4'
}

async function loadCapabilities() {
  loadingCapabilities.value = true
  capabilitiesError.value = ''
  try {
    const caps = await getKeyGenCapabilities()
    capabilities.value = caps

    // Auto-select valid provider
    if (caps.providers?.length) {
      const gm = caps.providers.find(p => p.id === 'gmssl')
      const op = caps.providers.find(p => p.id === 'openssl')
      if (gm?.available) {
        provider.value = 'gmssl'
      } else if (op?.available) {
        provider.value = 'openssl'
      }
    }
  } catch (err) {
    capabilities.value = null
    capabilitiesError.value = `获取密钥生成能力失败：${errorMessage(err)}。引擎不可用时禁止生成假密钥。`
  } finally {
    loadingCapabilities.value = false
  }
}

function initDialog() {
  error.value = ''
  storage.value = props.defaultStorage ?? 'MANAGED'
  password.value = ''

  const initialAlgo = inferInitialAlgoId()
  selectedAlgoId.value = initialAlgo
  if (initialAlgo === 'AES') aesBits.value = 128

  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '')
  name.value = `${initialAlgo}-Key-${dateStr}`
}

watch(() => props.visible, async val => {
  if (val) {
    capabilities.value = null
    initDialog()
    await loadCapabilities()
    // Verify initialAlgo is in availableAlgorithms, otherwise pick first available
    if (availableAlgorithms.value.length && !availableAlgorithms.value.some(a => a.id === selectedAlgoId.value)) {
      selectedAlgoId.value = availableAlgorithms.value[0].id
    }
  } else {
    password.value = ''
  }
}, { immediate: true })

watch(provider, () => {
  // If selected algorithm is not supported by newly selected provider, auto-switch
  if (availableAlgorithms.value.length && !availableAlgorithms.value.some(a => a.id === selectedAlgoId.value)) {
    selectedAlgoId.value = availableAlgorithms.value[0].id
  }
})

watch(selectedAlgoId, algoId => {
  const dateStr = new Date().toISOString().slice(0, 10).replace(/-/g, '')
  name.value = `${algoId}-Key-${dateStr}`
})

async function handleGenerate() {
  if (loading.value || loadingCapabilities.value || capabilitiesError.value) return
  if (!props.projectId) {
    error.value = '未选择当前项目'
    return
  }
  if (!currentProviderAvailable.value) {
    error.value = `当前选择的 ${provider.value} 引擎在部署环境中不可用`
    return
  }
  const opt = currentSelectedAlgo.value
  if (!opt) {
    error.value = '请选择受当前引擎支持的算法'
    return
  }

  loading.value = true
  error.value = ''
  try {
    const payload: GenerateKeyRequest = {
      provider: provider.value,
      algorithm: opt.payloadAlgorithm,
      name: name.value.trim() || `${opt.id}-Key`,
      storage: storage.value,
      ...(opt.kind === 'SYMMETRIC' ? {
        bits: opt.id === 'AES' ? aesBits.value : opt.defaultBits
      } : {}),
      ...(opt.kind === 'ASYMMETRIC' ? {
        ...(opt.payloadCurve ? { curve: opt.payloadCurve } : {}),
        ...(password.value ? { password: password.value } : {})
      } : {})
    }
    const res = await generateKey(props.projectId, payload)
    password.value = ''
    emit('generated', res)
    emit('update:visible', false)
  } catch (err) {
    error.value = errorMessage(err)
  } finally {
    loading.value = false
  }
}
</script>

<template>
  <div v-if="visible" class="modal-backdrop" @click.self="!loading && emit('update:visible', false)">
    <section class="modal key-generate-modal" role="dialog" aria-modal="true" aria-labelledby="keygen-title">
      <div class="modal-heading">
        <h2 id="keygen-title">生成加密密钥材料</h2>
        <button type="button" class="icon-button" aria-label="关闭对话框" :disabled="loading" @click="emit('update:visible', false)">×</button>
      </div>

      <div v-if="loadingCapabilities" class="banner notice" style="margin-bottom: 1rem">
        正在获取密码引擎密钥生成能力…
      </div>

      <div v-else-if="capabilitiesError" class="banner error" style="margin-bottom: 1rem">
        {{ capabilitiesError }}
      </div>

      <form v-else @submit.prevent="handleGenerate">
        <div v-if="error" class="banner error" style="margin-bottom: 1rem">{{ error }}</div>

        <div class="field">
          <label>生成来源 (SSL Engine / Provider) <span class="required">*</span></label>
          <div class="radio-inline-group" role="radiogroup" aria-label="生成引擎">
            <label v-for="p in availableProviders" :key="p.id" class="radio-label">
              <input type="radio" name="keygen-provider" :value="p.id" v-model="provider" :disabled="!p.available">
              <span>{{ p.id === 'gmssl' ? 'GmSSL 原生密码引擎' : 'OpenSSL 安全引擎' }} {{ !p.available ? (p.reason ? `（不可用: ${p.reason}）` : '（不可用）') : '' }}</span>
            </label>
          </div>
          <small class="muted">根据平台安全架构规范，由底层受控 SSL 引擎生成高熵密钥，杜绝伪随机弱密钥。</small>
        </div>

        <div class="field-grid">
          <div class="field">
            <label>密码算法 <span class="required">*</span></label>
            <select v-model="selectedAlgoId" aria-label="算法选择" :disabled="!availableAlgorithms.length">
              <option v-if="!availableAlgorithms.length" value="" disabled>当前引擎暂无可生成算法</option>
              <option v-for="a in availableAlgorithms" :key="a.id" :value="a.id">{{ a.name }}</option>
            </select>
          </div>

          <div v-if="selectedAlgoId === 'AES'" class="field">
            <label>密钥长度 (Bits) <span class="required">*</span></label>
            <select v-model.number="aesBits" aria-label="AES 长度">
              <option :value="128">128 位 (16 字节)</option>
              <option :value="192">192 位 (24 字节)</option>
              <option :value="256">256 位 (32 字节)</option>
            </select>
          </div>

          <div class="field" :class="{ 'wide': selectedAlgoId !== 'AES' }">
            <label>材料显示名称 <span class="required">*</span></label>
            <input v-model="name" required maxlength="120" placeholder="如 SM4-Key-01">
          </div>
        </div>

        <div v-if="isAsymmetric" class="field">
          <label>私钥加密口令 <span class="muted">（可选）</span></label>
          <input type="password" v-model="password" autocomplete="new-password" placeholder="留空由平台自动生成高熵随机口令并加密托管（使用时免重复输入）">
          <small class="muted">私钥文件口令由平台受控加密托管。后续在任务表单选择此私钥时将自动注入，无需反复手输。</small>
        </div>

        <div class="field section-line">
          <label>存储与托管模式 <span class="required">*</span></label>
          <div class="radio-inline-group" role="radiogroup" aria-label="存储模式">
            <label class="radio-label">
              <input type="radio" name="keygen-storage" value="MANAGED" v-model="storage">
              <span><strong>加密托管至项目密钥库</strong>（默认 · 推荐）</span>
            </label>
            <label class="radio-label">
              <input type="radio" name="keygen-storage" value="TEMPORARY" v-model="storage">
              <span><strong>仅本次任务使用</strong>（TEMPORARY · 执行后清理）</span>
            </label>
          </div>
          <small class="muted">
            {{ storage === 'MANAGED' ? '密钥材料经 AES-256-GCM 加密保存在服务端 Vault，后续可重复引用且受项目权限隔离。' : '材料仅用于当前任务或临时表单，不进入密钥库持久存储。' }}
          </small>
        </div>

        <div class="modal-actions" style="display:flex;justify-content:flex-end;gap:0.75rem;margin-top:1.5rem">
          <button type="button" class="button secondary" :disabled="loading" @click="emit('update:visible', false)">取消</button>
          <button type="submit" class="button primary" :disabled="loading || loadingCapabilities || !currentProviderAvailable || !currentSelectedAlgo">
            {{ loading ? '正在生成…' : '立即生成密钥' }}
          </button>
        </div>
      </form>
    </section>
  </div>
</template>
