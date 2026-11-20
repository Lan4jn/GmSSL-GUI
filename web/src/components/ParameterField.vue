<script setup lang="ts">
import { ref, computed, watch } from 'vue'
import type { Parameter, Key, ManagedFile, GenerateKeyResponse } from '../types'
import { isSecret, getDedicatedKeygenTool, isLinkedPassphraseManaged, getAllowedAlgorithmIds } from '../forms'
import { getKeyGenSpec, generateRandomHex } from '../key-generator'
import KeyGenerateDialog from './KeyGenerateDialog.vue'

const props = defineProps<{
  parameter: Parameter
  modelValue: unknown
  keys: Key[]
  files: ManagedFile[]
  error?: string
  keyOnly?: boolean
  toolId?: string
  values?: Record<string, unknown>
  projectId?: string
  editor?: boolean
}>()

const emit = defineEmits<{
  'update:modelValue': [unknown]
  'upload': [{ file: File; temporary: boolean }]
  'generatedKey': [Key?]
  'navigateTool': [string]
}>()

const cleanOnFinish = ref(true)
function upload(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) emit('upload', { file, temporary: cleanOnFinish.value })
  input.value = ''
}

const keySpec = computed(() => getKeyGenSpec(props.toolId, props.parameter))
const selectedBits = ref(128)
watch(keySpec, spec => {
  if (spec) selectedBits.value = spec.defaultBits
}, { immediate: true })

const showPlaintext = ref(false)
const genNotice = ref('')
const genError = ref('')
const showKeyGenDialog = ref(false)

const hasValue = computed(() => {
  if (props.modelValue === undefined || props.modelValue === null) return false
  return String(props.modelValue).trim().length > 0
})

const isManagedPassphrase = computed(() => {
  if (!props.parameter.credentialKeyParameter || !props.values) return false
  return isLinkedPassphraseManaged(props.parameter, props.values, props.keys, props.files)
})

const placeholderText = computed(() => {
  if (isManagedPassphrase.value && !props.modelValue) {
    return '已托管口令，执行时由平台自动注入（可留空；输入将覆盖）'
  }
  return props.parameter.formatHint ?? ''
})

const dedicatedKeygenTool = computed(() => {
  return getDedicatedKeygenTool(props.toolId, props.parameter)
})

const canGenerateSslKey = computed(() => {
  if (dedicatedKeygenTool.value || getAllowedAlgorithmIds(props.toolId, props.parameter)?.length === 0) return false
  if (props.parameter.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY')) return false
  if (props.parameter.allowedKeyKinds?.includes('MASTER_KEY')) return false
  if (keySpec.value || props.parameter.allowKeyReference) return true
  if (props.parameter.type === 'INPUT_FILE' && (props.parameter.allowedKeyKinds?.includes('PRIVATE_KEY') || props.parameter.allowedKeyKinds?.includes('PUBLIC_KEY'))) return true
  return false
})

function handleLocalRandomKey() {
  genError.value = ''
  if (!keySpec.value) return
  try {
    const bits = selectedBits.value || keySpec.value.defaultBits
    const bytes = bits / 8
    const hex = generateRandomHex(bytes)
    emit('update:modelValue', hex)
    genNotice.value = `已生成 ${bits} 位随机密钥（仅填入当前表单，未在密钥库托管；解密请自行妥善保留同一密钥）`
  } catch (err: unknown) {
    genError.value = (err instanceof Error && err.message) ? err.message : '浏览器随机源不可用'
  }
}

function onKeyGenerated(res: GenerateKeyResponse) {
  const expectsPublicKeyOnly = props.parameter.allowedKeyKinds?.includes('PUBLIC_KEY') && !props.parameter.allowedKeyKinds?.includes('PRIVATE_KEY')

  if (res.storage === 'MANAGED') {
    if (expectsPublicKeyOnly && !res.publicKey) {
      genError.value = '生成响应缺少公钥材料，请刷新材料列表后选择匹配公钥'
      emit('generatedKey')
      return
    }
    if (expectsPublicKeyOnly && res.publicKey) {
      emit('update:modelValue', `key:${res.publicKey.id}`)
      emit('generatedKey', res.publicKey)
      genNotice.value = `已通过 ${res.provider} 生成 ${res.algorithm} 密钥对，并已自动选择匹配公钥`
      return
    }

    if (res.reference) {
      emit('update:modelValue', res.reference)
    } else if (res.key) {
      emit('update:modelValue', `key:${res.key.id}`)
    }
    if (res.key) {
      emit('generatedKey', res.key)
    } else {
      emit('generatedKey')
    }
    genNotice.value = `已通过 ${res.provider} 生成 ${res.algorithm} 密钥并加密托管至密钥库`
  } else {
    if (expectsPublicKeyOnly) {
      if (res.temporaryPublicKeyFile) {
        emit('update:modelValue', `file:${res.temporaryPublicKeyFile.id}`)
      } else if (res.publicKey) {
        emit('update:modelValue', `key:${res.publicKey.id}`)
      } else {
        genError.value = '生成响应缺少公钥材料，请刷新材料列表后选择匹配公钥'
        emit('generatedKey')
        return
      }
      emit('generatedKey')
      genNotice.value = `已通过 ${res.provider} 生成临时密钥材料（仅本次任务有效）`
      return
    }

    if (res.reference) {
      emit('update:modelValue', res.reference)
    } else if (res.valueHex) {
      emit('update:modelValue', res.valueHex)
    } else if (res.temporaryFile) {
      emit('update:modelValue', `file:${res.temporaryFile.id}`)
    }
    emit('generatedKey')
    genNotice.value = `已通过 ${res.provider} 生成临时密钥材料（仅本次任务有效）`
  }
}

const booleanLabel = computed(() => {
  if (props.parameter.name === 'pkcs7_padding') {
    return 'PKCS#7 填充（普通文本建议开启）'
  }
  return props.parameter.label
})
</script>

<template>
  <div class="parameter-control">
    <div v-if="parameter.recommendation" class="param-recommendation-bar">
      <small class="recommendation-badge">推荐: {{ parameter.recommendation }}</small>
    </div>

    <label v-if="parameter.type === 'BOOLEAN'" class="toggle">
      <input type="checkbox" :checked="modelValue === true" @change="emit('update:modelValue',($event.target as HTMLInputElement).checked)">
      <span>{{ booleanLabel }}</span>
    </label>

    <template v-else-if="parameter.type === 'INPUT_FILE'">
      <div class="input-file-row">
        <select :value="modelValue" :aria-label="parameter.label" @change="emit('update:modelValue',($event.target as HTMLSelectElement).value)">
          <option value="">选择输入材料</option>
          <optgroup v-if="parameter.allowedKeyKinds?.length" label="托管密钥">
            <option v-for="key in keys.filter(k=>parameter.allowedKeyKinds?.includes(k.keyKind))" :key="key.id" :value="`key:${key.id}`">
              {{ key.name }} · {{ key.algorithm }}{{ key.hasManagedPassphrase ? ' [已托管口令]' : '' }} · {{ key.validationStatus }}
            </option>
          </optgroup>
          <optgroup v-if="!keyOnly" label="项目文件">
            <option v-for="file in files" :key="file.id" :value="`file:${file.id}`">
              {{ file.name }}{{ file.temporary ? ' · 临时' : '' }}{{ file.hasManagedPassphrase ? ' [已托管口令]' : '' }}
            </option>
          </optgroup>
        </select>

        <button
          v-if="dedicatedKeygenTool"
          type="button"
          class="button small secondary gen-ssl-btn"
          :title="`前往生成 ${dedicatedKeygenTool.label}`"
          @click="emit('navigateTool', dedicatedKeygenTool.targetTool)"
        >
          生成 {{ dedicatedKeygenTool.label }} ↗
        </button>

        <button
          v-else-if="canGenerateSslKey"
          type="button"
          class="button small secondary gen-ssl-btn"
          @click="showKeyGenDialog = true"
        >
          生成密钥对 (SSL)
        </button>
      </div>
      <div v-if="!keyOnly" class="file-upload-actions">
        <label class="upload-inline">上传输入文件<input type="file" @change="upload"></label>
        <label class="clean-toggle" title="任务执行结束后由服务端自动清理"><input type="checkbox" v-model="cleanOnFinish"> 任务结束清理</label>
      </div>
    </template>

    <select v-else-if="parameter.type === 'ENUM'" :value="modelValue" :aria-label="parameter.label" @change="emit('update:modelValue',($event.target as HTMLSelectElement).value)">
      <option value="">请选择</option>
      <option v-for="option in parameter.options" :key="option" :value="option">{{ option }}</option>
    </select>

    <template v-else>
      <div v-if="isManagedPassphrase" class="managed-passphrase-notice">
        <span>🔐 已关联托管密钥私钥口令：平台将自动安全注入，无需手输（输入新口令可覆盖）</span>
      </div>

      <div v-if="isSecret(parameter) && keySpec" class="secret-input-wrap">
        <input :value="modelValue" :aria-label="parameter.label" :type="showPlaintext ? 'text' : 'password'" autocomplete="new-password" :spellcheck="false" :placeholder="placeholderText" @input="emit('update:modelValue',($event.target as HTMLInputElement).value)">
        <button type="button" class="reveal-button" :aria-label="showPlaintext ? '隐藏密钥' : '显示密钥'" @click="showPlaintext = !showPlaintext">{{ showPlaintext ? '隐藏' : '显示' }}</button>
      </div>

      <input v-else :value="modelValue" :aria-label="parameter.label" :type="isSecret(parameter) ? 'password' : parameter.type === 'INTEGER' ? 'number' : 'text'" :min="parameter.min" :max="parameter.max" :autocomplete="isSecret(parameter) ? 'new-password' : 'off'" :spellcheck="false" :placeholder="placeholderText" @input="emit('update:modelValue',($event.target as HTMLInputElement).value)">

      <div v-if="keySpec || parameter.allowKeyReference" class="key-assist-bar">
        <button v-if="canGenerateSslKey" type="button" class="button small primary gen-key-button" @click="showKeyGenDialog = true">
          {{ hasValue ? '重新生成密钥 (SSL)' : '生成密钥 (SSL)' }}
        </button>
        <template v-if="keySpec">
          <select v-if="keySpec.options?.length" v-model.number="selectedBits" class="key-bits-select" aria-label="密钥长度">
            <option v-for="opt in keySpec.options" :key="opt.bits" :value="opt.bits">{{ opt.label }}</option>
          </select>
          <button type="button" class="button small secondary gen-key-button" @click="handleLocalRandomKey">
            {{ hasValue ? '覆盖生成随机密钥' : '随机生成密钥' }}
          </button>
        </template>
        <select v-if="parameter.allowKeyReference" :value="String(modelValue).startsWith('key:') ? modelValue : ''" :aria-label="`${parameter.label}托管引用`" @change="emit('update:modelValue',($event.target as HTMLSelectElement).value)">
          <option value="">或选托管对称密钥</option>
          <option v-for="key in keys.filter(k=>k.keyKind==='SYMMETRIC_KEY')" :key="key.id" :value="`key:${key.id}`">
            {{ key.name }} · {{ key.encoding }}
          </option>
        </select>
      </div>

    </template>

      <div v-if="genNotice" class="keygen-notice" style="margin-top: 0.5rem; color: var(--color-success, #2e7d32); font-size: 0.85rem">
        {{ genNotice }}
      </div>
      <div v-if="genError" class="field-error" style="margin-top: 0.25rem">
        {{ genError }}
      </div>

    <span v-if="error" class="field-error" style="display:block;margin-top:0.25rem">{{ error }}</span>

    <KeyGenerateDialog
      v-if="canGenerateSslKey"
      v-model:visible="showKeyGenDialog"
      :project-id="projectId ?? ''"
      :target-parameter="parameter"
      :tool-id="toolId"
      default-storage="MANAGED"
      @generated="onKeyGenerated"
    />
  </div>
</template>
