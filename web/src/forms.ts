import type { Parameter, Tool, User, Project, Key, ManagedFile } from './types'
export type ParamValues = Record<string, unknown>
export function isSecret(p: Parameter) { return p.secret === true || p.type === 'SECRET' }
export function isAdvancedParameter(p: Parameter): boolean {
  if (p.advanced !== true) return false
  // 必须严格遵守契约：required 无 default 不能被折叠隐藏
  const hasDefault = p.defaultValue !== undefined && p.defaultValue !== null && p.defaultValue !== ''
  if (p.required && !hasDefault) return false
  return true
}
export function isLinkedPassphraseManaged(p: Parameter, values: ParamValues, keys?: Key[], files?: ManagedFile[]): boolean {
  if (!p.credentialKeyParameter) return false
  const ref = values[p.credentialKeyParameter]
  if (typeof ref === 'string') {
    if (ref.startsWith('key:')) {
      const keyId = ref.slice(4)
      const targetKey = keys?.find(k => k.id === keyId)
      return targetKey?.hasManagedPassphrase === true
    }
    if (ref.startsWith('file:')) {
      const fileId = ref.slice(5)
      const targetFile = files?.find(f => f.id === fileId)
      return targetFile?.hasManagedPassphrase === true
    }
  }
  return false
}
export function getDedicatedKeygenTool(toolId?: string, p?: Parameter): { targetTool: string; label: string } | null {
  if (!toolId || !p || p.type !== 'INPUT_FILE') return null
  if (!p.allowedKeyKinds?.length && !['key', 'pubkey', 'pubmaster', 'exch_key'].includes(p.name)) return null
  const t = toolId.toLowerCase()
  if (t.startsWith('sm9')) {
    if (t === 'sm9keygen' && p.name === 'in') {
      return { targetTool: 'sm9setup', label: 'SM9 主密钥 (sm9setup)' }
    }
    if ((t === 'sm9sign' || t === 'sm9decrypt' || t === 'sm9exch') && p.name === 'key') {
      return { targetTool: 'sm9keygen', label: 'SM9 私钥 (sm9keygen)' }
    }
    if ((t === 'sm9verify' || t === 'sm9encrypt' || t === 'sm9exch') && (p.name === 'pubmaster' || p.name === 'in')) {
      return { targetTool: 'sm9setup', label: 'SM9 主公钥 (sm9setup)' }
    }
    return { targetTool: 'sm9keygen', label: 'SM9 专用密钥 (sm9keygen)' }
  }
  if (t.startsWith('lms') && (p.allowedKeyKinds?.length || p.name === 'key')) {
    return { targetTool: 'lmskeygen', label: 'LMS 状态私钥 (lmskeygen)' }
  }
  if (t.startsWith('hss') && (p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY') || p.name === 'key')) {
    return { targetTool: 'hsskeygen', label: 'HSS 状态私钥 (hsskeygen)' }
  }
  if (t.startsWith('xmssmt') && (p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY') || p.name === 'key')) {
    return { targetTool: 'xmssmtkeygen', label: 'XMSSMT 状态私钥 (xmssmtkeygen)' }
  }
  if (t.startsWith('xmss') && (p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY') || p.name === 'key')) {
    return { targetTool: 'xmsskeygen', label: 'XMSS 状态私钥 (xmsskeygen)' }
  }
  if (t.startsWith('sphincs') && (p.name === 'key' || p.name === 'pubkey')) {
    return { targetTool: 'sphincskeygen', label: 'SPHINCS+ 密钥 (sphincskeygen)' }
  }
  if (t.startsWith('kyber') && (p.name === 'key' || p.name === 'pubkey')) {
    return { targetTool: 'kyberkeygen', label: 'Kyber 密钥 (kyberkeygen)' }
  }
  return null
}
export function getAllowedAlgorithmIds(toolId?: string, targetParameter?: Parameter): string[] | null {
  if (targetParameter?.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY')) return []
  if (targetParameter?.allowedKeyKinds?.includes('MASTER_KEY')) return []

  const t = (toolId || '').toLowerCase()

  // Dedicated keygen tools or unsupported tools return empty
  if (t.startsWith('sm9') || t.startsWith('lms') || t.startsWith('hss') || t.startsWith('xmss') || t.startsWith('sphincs') || t.startsWith('kyber') || t.startsWith('dilithium') || t.startsWith('falcon')) {
    return []
  }

  if (t === 'sm4_xts') return ['SM4-XTS']
  if (t.startsWith('sm4')) return ['SM4']
  if (t.startsWith('aes')) return ['AES']
  if (t.includes('zuc256') || t.includes('zuc-256')) return ['ZUC256']
  if (t.startsWith('zuc')) return ['ZUC']
  if (t.startsWith('hmac')) return ['HMAC']

  if (t === 'eckeygen') return ['P-256', 'P-384']
  if (t.startsWith('sm2') || t.startsWith('tlcp') || t === 'sm3') return ['SM2']
  if (t.startsWith('tls12') || t.startsWith('tls13') || t === 'sctverify' || t === 'quic_server') return ['SM2', 'P-256', 'P-384']
  if (t === 'certgen' || t === 'reqgen' || t === 'reqsign' || t === 'crlgen' || t === 'ocspsign' || t === 'cmssign' || t === 'cmsdecrypt') {
    return ['SM2', 'P-256', 'P-384']
  }

  if (targetParameter?.type === 'HEX') {
    return ['SM4', 'SM4-XTS', 'AES', 'ZUC', 'ZUC256', 'HMAC']
  }
  if (targetParameter?.type === 'INPUT_FILE') return []
  return null
}
export function defaults(tool: Tool): ParamValues {
  const hasEncDec = tool.parameters.some(p => p.name === 'encrypt' && p.type === 'BOOLEAN') &&
                    tool.parameters.some(p => p.name === 'decrypt' && p.type === 'BOOLEAN')
  const isSm4PaddingTool = tool.command === 'sm4_cbc' || tool.id === 'sm4_cbc'
  return Object.fromEntries(tool.parameters.map(p => {
    let def = p.defaultValue
    if (hasEncDec && p.type === 'BOOLEAN') {
      if (p.name === 'encrypt') def = true
      if (p.name === 'decrypt') def = false
    }
    if (isSm4PaddingTool && p.name === 'pkcs7_padding' && p.type === 'BOOLEAN') {
      def = true
    }
    return [
      p.name,
      isSecret(p) ? (p.repeatable ? [] : '') : p.repeatable ? (Array.isArray(def) ? [...def] : []) : def ?? (p.type === 'BOOLEAN' ? false : '')
    ]
  }))
}
export const canManage = (user: User | null, project?: Project) => !!user && !!project && (user.role === 'ADMIN' || project.role === 'OWNER')
export const canEdit = (user: User | null, project?: Project) => !!user && !!project && (user.role === 'ADMIN' || project.role === 'OWNER' || project.role === 'EDITOR')
export function canRun(user: User | null, project: Project | undefined, tool: Tool) { return canEdit(user,project) && (!tool.adminOnly || user?.role === 'ADMIN') && tool.verification.status !== 'unavailable' }
export function validateParameter(p: Parameter, value: unknown, isPassphraseManaged = false): string | undefined {
  if (value === undefined || value === null || value === '') {
    if (isPassphraseManaged) return undefined
    return p.required ? '此项为必填' : undefined
  }
  if (p.type === 'BOOLEAN') return typeof value === 'boolean' ? undefined : '请选择开关状态'
  if (typeof value !== 'string' && typeof value !== 'number') return '参数格式不正确'
  const text = String(value)
  if (p.type === 'HEX' && p.allowKeyReference && /^key:[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) return undefined
  if (p.type === 'INTEGER' && (!/^-?\d+$/.test(text) || !Number.isSafeInteger(Number(text)) || (p.min !== undefined && Number(text)<p.min) || (p.max !== undefined && Number(text)>p.max))) return `请输入整数${p.min !== undefined ? `，最小 ${p.min}` : ''}${p.max !== undefined ? `，最大 ${p.max}` : ''}`
  if (p.type === 'ENUM' && !p.options?.includes(text)) return '请选择目录声明的选项'
  if (p.type === 'HEX' && (!/^[0-9a-f]+$/i.test(text) || text.length % 2 !== 0)) return '请输入偶数位十六进制字符'
  if (p.type === 'INPUT_FILE' && !/^(key|file):[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(text)) return '请选择本项目的文件或托管密钥'
  if (p.type === 'INPUT_FILE' && text.startsWith('key:') && !p.allowedKeyKinds?.length) return '此参数只接受项目文件引用'
  if (p.type === 'OUTPUT_FILE' && (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$/.test(text) || text.includes('..'))) return '使用简单文件名（字母、数字、点、下划线、短横线），不含路径'
  return undefined
}
export function buildParameters(tool: Tool, values: ParamValues, keys?: Key[], files?: ManagedFile[]): {parameters:ParamValues;errors:Record<string,string>} {
  const parameters: ParamValues = {}; const errors: Record<string,string> = {}
  for (const p of tool.parameters) {
    const raw = values[p.name]; const list = p.repeatable ? Array.isArray(raw) ? raw : [] : [raw]
    const passManaged = isLinkedPassphraseManaged(p, values, keys, files)
    if (p.repeatable && raw !== undefined && !Array.isArray(raw)) errors[p.name] = '重复参数必须为数组'
    if (p.repeatable && p.required && list.length === 0 && !passManaged) errors[p.name] = '请至少添加一项'
    for (const value of list) {
      const error = tool.stateful && p.type === 'INPUT_FILE' && p.allowedKeyKinds?.includes('STATEFUL_PRIVATE_KEY') && typeof value === 'string' && !value.startsWith('key:')
        ? '状态型签名仅接受托管状态型私钥引用'
        : validateParameter(p, value, passManaged)
      if (error) errors[p.name] = error
    }
    const converted = list.filter(v => v !== '' && v !== undefined && v !== null).map(v => p.type === 'INTEGER' ? Number(v) : v)
    if (converted.length > 0) {
      parameters[p.name] = p.repeatable ? converted : converted[0]
    }
  }
  const hasEncrypt = tool.parameters.some(p => p.name === 'encrypt' && p.type === 'BOOLEAN')
  const hasDecrypt = tool.parameters.some(p => p.name === 'decrypt' && p.type === 'BOOLEAN')
  if (hasEncrypt && hasDecrypt) {
    const enc = values['encrypt'] === true
    const dec = values['decrypt'] === true
    if (enc && dec) {
      errors['encrypt'] = '加密与解密为互斥操作，请仅选择一项'
      errors['decrypt'] = '加密与解密为互斥操作，请仅选择一项'
    } else if (!enc && !dec) {
      errors['encrypt'] = '请选择操作模式：加密 (-encrypt) 或解密 (-decrypt)'
    }
  }
  const toolCmd = (tool.command || tool.id || '').toLowerCase()
  if (toolCmd.startsWith('sm4_') && toolCmd !== 'sm4_cbc_mac') {
    const rawKey = values['key']
    if (typeof rawKey === 'string' && rawKey.trim().length > 0 && !rawKey.startsWith('key:') && !errors['key']) {
      const hexKey = rawKey.trim()
      if (/^[0-9a-f]+$/i.test(hexKey)) {
        if (toolCmd === 'sm4_xts') {
          if (hexKey.length !== 64) errors['key'] = 'SM4-XTS 密钥必须为 32 字节（64 位十六进制字符）'
        } else {
          if (hexKey.length !== 32) errors['key'] = 'SM4 密钥必须为 16 字节（32 位十六进制字符）'
        }
      }
    }
  }
  return {parameters,errors}
}
