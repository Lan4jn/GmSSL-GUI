<script setup lang="ts">
import { ref, watch, computed } from 'vue'
import type { Tool, Key, ManagedFile } from '../types'
import { defaults, buildParameters, isSecret, isAdvancedParameter, type ParamValues } from '../forms'
import ParameterField from './ParameterField.vue'

const props = defineProps<{
  tool: Tool
  keys: Key[]
  files: ManagedFile[]
  disabled: boolean
  busy: boolean
  projectId?: string
  editor?: boolean
}>()

const emit = defineEmits<{
  run: [{ toolId: string; parameters: ParamValues; stdinText?: string; stdinFileRef?: string; timeoutSeconds: number }]
  upload: [{ file: File; parameter?: string; index?: number; temporary: boolean; isStdin?: boolean }]
  refreshKeys: []
  navigateTool: [string]
}>()

const values = ref<ParamValues>({})
const errors = ref<Record<string, string>>({})
const stdin = ref('')
const stdinFileRef = ref('')
const stdinMode = ref('text')
const timeout = ref(30)
const stdinCleanOnFinish = ref(true)
const showAdvanced = ref(false)

const hasEncDec = computed(() =>
  props.tool.parameters.some(p => p.name === 'encrypt' && p.type === 'BOOLEAN') &&
  props.tool.parameters.some(p => p.name === 'decrypt' && p.type === 'BOOLEAN')
)

const displayParameters = computed(() => {
  if (!hasEncDec.value) return props.tool.parameters
  return props.tool.parameters.filter(p => p.name !== 'encrypt' && p.name !== 'decrypt')
})

const hasAdvancedParams = computed(() =>
  displayParameters.value.some(p => isAdvancedParameter(p))
)

const advancedParamsCount = computed(() =>
  displayParameters.value.filter(p => isAdvancedParameter(p)).length
)

const visibleParameters = computed(() => {
  if (showAdvanced.value) return displayParameters.value
  return displayParameters.value.filter(p => !isAdvancedParameter(p))
})

watch(() => props.tool, tool => {
  values.value = defaults(tool)
  errors.value = {}
  stdin.value = ''
  stdinFileRef.value = ''
  timeout.value = tool.defaultTimeoutSeconds
  showAdvanced.value = false
}, { immediate: true })

watch([stdin, stdinFileRef, stdinMode], () => {
  if (errors.value['stdin']) delete errors.value['stdin']
})

function setValue(name: string, value: unknown, index?: number) {
  if (index === undefined) {
    values.value[name] = value
    if (name === 'encrypt' && value === true && 'decrypt' in values.value) {
      values.value['decrypt'] = false
    } else if (name === 'decrypt' && value === true && 'encrypt' in values.value) {
      values.value['encrypt'] = false
    }
  } else {
    (values.value[name] as unknown[])[index] = value
  }
  if (errors.value[name]) {
    delete errors.value[name]
  }
}

function setOperationMode(mode: 'encrypt' | 'decrypt') {
  if (mode === 'encrypt') {
    values.value['encrypt'] = true
    values.value['decrypt'] = false
  } else {
    values.value['encrypt'] = false
    values.value['decrypt'] = true
  }
  if (errors.value['encrypt']) delete errors.value['encrypt']
  if (errors.value['decrypt']) delete errors.value['decrypt']
}

function setUploadedReference(name: string, reference: string, index?: number) {
  setValue(name, reference, index)
}

function setUploadedStdin(reference: string) {
  stdinFileRef.value = reference
}

defineExpose({ setUploadedReference, setUploadedStdin })

function onParamUpload(payload: { file: File; temporary: boolean }, name: string, index?: number) {
  emit('upload', { file: payload.file, temporary: payload.temporary, parameter: name, index })
}

function uploadStdin(event: Event) {
  const input = event.target as HTMLInputElement
  const file = input.files?.[0]
  if (file) emit('upload', { file, temporary: stdinCleanOnFinish.value, isStdin: true })
  input.value = ''
}

function submit() {
  if (props.disabled || props.busy) return
  const result = buildParameters(props.tool, values.value, props.keys, props.files)
  errors.value = result.errors

  const toolCmd = (props.tool.command || props.tool.id || '').toLowerCase()
  if (toolCmd.startsWith('sm4_') && toolCmd !== 'sm4_ff1' && toolCmd !== 'sm4_cbc_mac') {
    const hasInFile = !!values.value['in'] && String(values.value['in']).length > 0
    const hasInStr = !!values.value['in_str'] && String(values.value['in_str']).length > 0
    const hasStdinText = stdinMode.value === 'text'
    const hasStdinFile = stdinMode.value === 'file' && !!stdinFileRef.value && String(stdinFileRef.value).length > 0
    if (!hasInFile && !hasInStr && !hasStdinText && !hasStdinFile) {
      errors.value['in'] = '请选择输入文件 (-in) 或在下方选择项目文件作为标准输入'
    }

    if (toolCmd === 'sm4_ecb' && stdinMode.value === 'text') {
      const byteLen = new TextEncoder().encode(stdin.value).length
      if (byteLen % 16 !== 0) {
        errors.value['stdin'] = `SM4 ECB 模式无填充，输入长度须为 16 字节整数倍（当前为 ${byteLen} 字节）`
      }
    } else if (toolCmd === 'sm4_ecb' && stdinMode.value === 'file' && stdinFileRef.value) {
      const fileId = stdinFileRef.value.startsWith('file:') ? stdinFileRef.value.slice(5) : stdinFileRef.value
      const targetFile = props.files.find(f => f.id === fileId)
      if (targetFile && typeof targetFile.size === 'number' && targetFile.size % 16 !== 0) {
        errors.value['stdin'] = `SM4 ECB 模式无填充，输入文件大小须为 16 字节整数倍（当前为 ${targetFile.size} 字节）`
      }
    }
  }

  if (!Number.isInteger(timeout.value) || timeout.value < 1 || timeout.value > props.tool.maxTimeoutSeconds) {
    errors.value.timeout = '超出任务超时范围'
  }
  if (Object.keys(errors.value).length) return

  emit('run', {
    toolId: props.tool.id,
    parameters: result.parameters,
    ...(props.tool.acceptsStdin && stdinMode.value === 'text' && stdin.value !== undefined ? { stdinText: stdin.value } : {}),
    ...(props.tool.acceptsStdin && stdinMode.value === 'file' && stdinFileRef.value ? { stdinFileRef: stdinFileRef.value } : {}),
    timeoutSeconds: timeout.value
  })

  for (const p of props.tool.parameters) {
    if (isSecret(p)) values.value[p.name] = p.repeatable ? [] : ''
  }
  stdin.value = ''
}
</script>

<template>
  <form class="tool-form" @submit.prevent="submit">
    <div v-if="tool.stateful" class="notice">
      状态型操作：仅使用受平台串行化保护的托管状态型私钥；任务后密钥状态由服务端提交。
    </div>

    <fieldset :disabled="disabled || busy">
      <div v-if="hasEncDec" class="field wide section-line">
        <label>操作模式 <span class="required">*</span> <code>-encrypt / -decrypt</code></label>
        <div class="radio-inline-group" role="radiogroup" aria-label="操作模式">
          <label class="radio-label">
            <input type="radio" name="operation-mode" value="encrypt" :checked="values['encrypt'] === true" @change="setOperationMode('encrypt')">
            <span>加密 (-encrypt)</span>
          </label>
          <label class="radio-label">
            <input type="radio" name="operation-mode" value="decrypt" :checked="values['decrypt'] === true" @change="setOperationMode('decrypt')">
            <span>解密 (-decrypt)</span>
          </label>
        </div>
        <span v-if="errors['encrypt'] || errors['decrypt']" class="field-error">
          {{ errors['encrypt'] || errors['decrypt'] }}
        </span>
      </div>

      <div v-if="hasAdvancedParams" class="field wide form-mode-bar">
        <div class="form-mode-switch">
          <button type="button" class="button small secondary mode-toggle-button" @click="showAdvanced = !showAdvanced">
            {{ showAdvanced ? '折叠高级参数' : `展开高级参数 (含 ${advancedParamsCount} 项)` }}
          </button>
          <span class="mode-tip muted">
            {{ showAdvanced ? '当前显示完整高级参数配置；常用参数置顶。' : '当前显示常用快捷参数；已自动折叠可选高级参数。' }}
          </span>
        </div>
      </div>

      <div class="field-grid">
        <div v-for="p in visibleParameters" :key="p.name" class="field" :class="{ 'wide': p.type === 'INPUT_FILE' }">
          <label v-if="p.type !== 'BOOLEAN'">
            {{ p.label }}
            <span v-if="p.required" class="required">*</span>
            <code>{{ p.flag }}</code>
            <span v-if="isSecret(p)" class="secret-tag">秘密</span>
            <span v-if="p.advanced" class="advanced-tag">高级</span>
          </label>

          <template v-if="p.repeatable">
            <div v-for="(v, i) in (values[p.name] as unknown[])" :key="i" class="repeat-row">
              <ParameterField
                :parameter="p"
                :tool-id="tool.id"
                :project-id="projectId"
                :editor="editor"
                :values="values"
                :key-only="tool.stateful && !!p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY')"
                :model-value="v"
                :keys="keys"
                :files="files"
                :error="errors[p.name]"
                @update:model-value="setValue(p.name, $event, i)"
                @upload="onParamUpload($event, p.name, i)"
                @generated-key="emit('refreshKeys')"
                @navigate-tool="emit('navigateTool', $event)"
              />
              <button type="button" class="icon-button" aria-label="移除此参数" @click="(values[p.name] as unknown[]).splice(i, 1)">−</button>
            </div>
            <button type="button" class="button small secondary" @click="(values[p.name] as unknown[]).push(p.type === 'BOOLEAN' ? false : '')">＋ 添加参数</button>
            <span v-if="errors[p.name]" class="field-error">{{ errors[p.name] }}</span>
          </template>

          <ParameterField
            v-else
            :parameter="p"
            :tool-id="tool.id"
            :project-id="projectId"
            :editor="editor"
            :values="values"
            :key-only="tool.stateful && !!p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY')"
            :model-value="values[p.name]"
            :keys="keys"
            :files="files"
            :error="errors[p.name]"
            @update:model-value="setValue(p.name, $event)"
            @upload="onParamUpload($event, p.name)"
            @generated-key="emit('refreshKeys')"
            @navigate-tool="emit('navigateTool', $event)"
          />
          <small>{{ p.description }}</small>
        </div>
      </div>

      <div v-if="tool.parameters.length === 0" class="notice">
        此工具无需附加参数。执行仍受平台权限与资源限制。
      </div>

      <div v-if="tool.command === 'sm4_ecb' || tool.id === 'sm4_ecb'" class="notice">
        SM4 ECB 模式说明：GmSSL 原生实现无填充，输入数据长度必须为 16 字节整数倍。
      </div>

      <div v-if="tool.acceptsStdin" class="field wide section-line">
        <label>标准输入 <span class="muted">可选 · 文本或文件</span></label>
        <div class="segmented">
          <button type="button" :class="{ active: stdinMode === 'text' }" @click="stdinMode = 'text'">文本输入</button>
          <button type="button" :class="{ active: stdinMode === 'file' }" @click="stdinMode = 'file'">项目文件</button>
        </div>
        <textarea
          v-if="stdinMode === 'text'"
          v-model="stdin"
          rows="4"
          placeholder="输入待处理文本，按原文发送"
          autocomplete="off"
          spellcheck="false"
        />
        <template v-else>
          <select v-model="stdinFileRef">
            <option value="">选择项目文件</option>
            <option v-for="file in files" :key="file.id" :value="`file:${file.id}`">
              {{ file.name }}{{ file.temporary ? ' · 临时' : '' }}
            </option>
          </select>
          <div class="file-upload-actions">
            <label class="upload-inline">上传输入文件<input type="file" @change="uploadStdin"></label>
            <label class="clean-toggle" title="任务执行结束后由服务端自动清理">
              <input type="checkbox" v-model="stdinCleanOnFinish"> 任务结束清理
            </label>
          </div>
        </template>
        <small>输入仅用于本次任务。秘密不会保存至浏览器持久存储。</small>
        <span v-if="errors.stdin" class="field-error" style="display: block; margin-top: 6px">{{ errors.stdin }}</span>
      </div>

      <div class="run-bar">
        <div class="field">
          <label>超时（秒）</label>
          <input v-model.number="timeout" type="number" min="1" :max="tool.maxTimeoutSeconds">
          <small v-if="errors.timeout" class="field-error">{{ errors.timeout }}</small>
          <small v-else>上限 {{ tool.maxTimeoutSeconds }} 秒</small>
        </div>
        <button class="button primary" type="submit" :disabled="disabled || busy">
          {{ busy ? '正在提交…' : '运行任务 ↗' }}
        </button>
      </div>
    </fieldset>
  </form>
</template>
