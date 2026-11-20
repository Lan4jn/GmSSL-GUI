import { post, errorMessage, request } from './api'
import type { Key, ManagedFile, KeyGenerationCapabilities } from './types'

export type CertificateProfile =
  | 'SELF_SIGNED'
  | 'ROOT_CA'
  | 'INTERMEDIATE_CA'
  | 'CSR'
  | 'CA_SIGN'
  | 'TLCP'
  | 'QUICK_ISSUE'
  | 'QUICK_ISSUE'

export type CertificatePurpose = 'SERVER' | 'CLIENT' | 'SIGNING'

export interface CertificateSubject {
  CN?: string
  C?: string
  ST?: string
  L?: string
  O?: string
  OU?: string
}

export interface CertificateWorkflowRequest {
  profile: CertificateProfile
  name: string
  subject?: CertificateSubject
  sanDns?: string[]
  sanIps?: string[]
  days?: number
  provider?: 'gmssl' | 'openssl'
  keyRef?: string
  keyPassword?: string
  issuerCertRef?: string
  issuerKeyRef?: string
  issuerPassword?: string
  csrRef?: string
  purpose?: CertificatePurpose
  advanced?: {
    pathLenConstraint?: number
    sm2Id?: string
    serialLen?: number
    [key: string]: unknown
  }
}

export interface WorkflowStage {
  name: string
  jobId?: string
  status: 'PENDING' | 'RUNNING' | 'SUCCEEDED' | 'FAILED' | 'SKIPPED'
}

export interface CertificateWorkflowResponse {
  workflowId: string
  status: 'SUCCEEDED' | 'FAILED' | 'RUNNING'
  stages: WorkflowStage[]
  keys?: Key[]
  files?: ManagedFile[]
  artifacts?: unknown[]
  warnings?: string[]
  error?: string
}

export interface ProfileMeta {
  id: CertificateProfile
  title: string
  badge: string
  description: string
  defaultDays: number
  supportsPurpose: boolean
  supportsSan: boolean
  requiresIssuer: boolean
  requiresCsr: boolean
  isDualKey: boolean
}

export const PROFILES: Record<CertificateProfile, ProfileMeta> = {
  SELF_SIGNED: {
    id: 'SELF_SIGNED',
    title: '单证自签名证书',
    badge: '单证直签',
    description: '快速生成自带私钥的自签名 X.509 证书，适合本地测试与内网点对点通信。',
    defaultDays: 365,
    supportsPurpose: true,
    supportsSan: true,
    requiresIssuer: false,
    requiresCsr: false,
    isDualKey: false
  },
  ROOT_CA: {
    id: 'ROOT_CA',
    title: '自签名根 CA 证书',
    badge: '信任根',
    description: '建立独立的国密根证书签发权威，签发下级中间 CA 或终道证书。',
    defaultDays: 3650,
    supportsPurpose: false,
    supportsSan: false,
    requiresIssuer: false,
    requiresCsr: false,
    isDualKey: false
  },
  INTERMEDIATE_CA: {
    id: 'INTERMEDIATE_CA',
    title: '中间 CA 证书',
    badge: '二级CA',
    description: '由现有根 CA 证书及私钥签发，用于隔离根 CA 密钥并签发业务终端证书。',
    defaultDays: 1825,
    supportsPurpose: false,
    supportsSan: false,
    requiresIssuer: true,
    requiresCsr: false,
    isDualKey: false
  },
  CSR: {
    id: 'CSR',
    title: '证书签名请求 (CSR)',
    badge: '请求文件',
    description: '生成 PKCS#10 证书申请文件及对应私钥，用于提交给外部 CA 机构进行签发。',
    defaultDays: 365,
    supportsPurpose: true,
    supportsSan: true,
    requiresIssuer: false,
    requiresCsr: false,
    isDualKey: false
  },
  CA_SIGN: {
    id: 'CA_SIGN',
    title: 'CA 签发证书',
    badge: '正式签发',
    description: '使用项目内的 CA 证书和私钥对现存 CSR 申请文件进行认证签发。',
    defaultDays: 365,
    supportsPurpose: true,
    supportsSan: true,
    requiresIssuer: true,
    requiresCsr: true,
    isDualKey: false
  },
  TLCP: {
    id: 'TLCP',
    title: 'TLCP 国密双证书',
    badge: '国密TLCP',
    description: '按 GB/T 38636 规范同时签发独立的签名与加密 SM2 双密钥对及双证书。',
    defaultDays: 365,
    supportsPurpose: false,
    supportsSan: true,
    requiresIssuer: false,
    requiresCsr: false,
    isDualKey: true
  },
  QUICK_ISSUE: {
    id: 'QUICK_ISSUE',
    title: '快速签发服务证书',
    badge: '一键签发',
    description: '通过已有 CA 证书全自动生成私钥与证书请求并签名，一步直达最终证书与证书链。',
    defaultDays: 365,
    supportsPurpose: true,
    supportsSan: true,
    requiresIssuer: true,
    requiresCsr: false,
    isDualKey: false
  }
}

/**
 * 验证单条 SAN 条目：
 * - 拒绝 URI/协议/路径/空格/端口/截断/畸形字符
 * - IPv4: 严格 4 组十进制数字（0..255），禁止前导零（如 01.1.1.1）与超范围数字（999.999.999.999）
 * - IPv6: 必须包含冒号且通过标准浏览器 URL IPv6 字面量构造校验（拒绝 :::、1:2 等）
 * - DNS 域名与主机名：
 *   - 允许内网单标签主机名（如 localhost, labnode, node-1；禁止纯数字主机名如 123）
 *   - 允许标准多级域名及 IDNA ASCII Punycode TLD (如 xn--fiqs8s)
 *   - 允许通配符且仅限最左侧 (*.)，拒绝 foo.*.com 或单纯 *
 *   - 标签 1~63 字符，只含字母数字连字符，禁止连字符开头或结尾
 *   - 禁止纯数字顶级域名（如 example.123）
 */
export function validateSanEntry(entry: string): { type: 'dns' | 'ip' | 'invalid'; valid: boolean; error?: string } {
  const trimmed = entry.trim()
  if (!trimmed) {
    return { type: 'invalid', valid: false, error: 'SAN 条目不能为空' }
  }

  // 严禁包含协议头、路径、查询参数、用户信息、端口号或空白
  if (
    trimmed.includes('/') ||
    trimmed.includes(' ') ||
    trimmed.includes('?') ||
    trimmed.includes('#') ||
    trimmed.includes('@') ||
    trimmed.startsWith('http://') ||
    trimmed.startsWith('https://')
  ) {
    return { type: 'invalid', valid: false, error: `无效的 SAN 格式，不得包含协议、路径、端口或空格: ${trimmed}` }
  }

  // 1. IPv4 严格校验：恰好 4 段十进制，每段 0..255，且禁止无意义前导零
  const ipv4Parts = trimmed.split('.')
  if (ipv4Parts.length === 4 && ipv4Parts.every(p => /^(0|[1-9]\d{0,2})$/.test(p) && Number(p) <= 255)) {
    return { type: 'ip', valid: true }
  }

  // 2. IPv6 严格校验：必须包含冒号，且禁止方括号输入，通过浏览器标准 URL 解析器验证合法性
  if (trimmed.includes(':') && !trimmed.includes('[') && !trimmed.includes(']')) {
    try {
      const u = new URL(`http://[${trimmed}]`)
      if (u.hostname === `[${trimmed.toLowerCase()}]` || u.hostname.startsWith('[')) {
        return { type: 'ip', valid: true }
      }
    } catch {
      return { type: 'invalid', valid: false, error: `无效的 IPv6 地址: ${trimmed}` }
    }
  }

  // 3. DNS 域名与主机名校验
  let domainPart = trimmed
  if (trimmed.startsWith('*.')) {
    domainPart = trimmed.slice(2)
    if (!domainPart || domainPart.includes('*')) {
      return { type: 'invalid', valid: false, error: `通配符仅允许位于最左侧 (*.): ${trimmed}` }
    }
  } else if (trimmed.includes('*')) {
    return { type: 'invalid', valid: false, error: `通配符仅允许位于最左侧 (*.): ${trimmed}` }
  }

  if (domainPart.length > 253) {
    return { type: 'invalid', valid: false, error: `域名或主机名总长度不得超过 253 字符: ${trimmed}` }
  }

  const labels = domainPart.split('.')

  // 检查各级标签规范
  for (let i = 0; i < labels.length; i++) {
    const l = labels[i]
    if (!l || l.length > 63) {
      return { type: 'invalid', valid: false, error: `各级标签长度必须在 1~63 字符之间: ${trimmed}` }
    }
    if (l.startsWith('-') || l.endsWith('-')) {
      return { type: 'invalid', valid: false, error: `标签不能以连字符开头或结尾: ${trimmed}` }
    }
    if (!/^[a-zA-Z0-9-]+$/.test(l)) {
      return { type: 'invalid', valid: false, error: `标签只能包含英文字母、数字与连字符: ${trimmed}` }
    }
  }

  // 单标签内网主机名校验（如 localhost, labnode, node-1）
  if (labels.length === 1) {
    const label = labels[0]
    if (/^\d+$/.test(label)) {
      return { type: 'invalid', valid: false, error: `主机名不能为纯数字: ${trimmed}` }
    }
    return { type: 'dns', valid: true }
  }

  // 多级域名：校验顶级域名 (TLD)
  const tld = labels[labels.length - 1]
  if (/^\d+$/.test(tld)) {
    return { type: 'invalid', valid: false, error: `顶级域名不能为纯数字: ${trimmed}` }
  }
  const isAlphaTld = /^[a-zA-Z]{2,}$/.test(tld)
  const isPunycodeTld = /^xn--[a-zA-Z0-9]+$/i.test(tld)
  if (!isAlphaTld && !isPunycodeTld) {
    return { type: 'invalid', valid: false, error: `顶级域名必须由不少于2位的字母或合法 Punycode (xn--) 组成: ${trimmed}` }
  }

  return { type: 'dns', valid: true }
}

export function parseSanEntries(entries: string[]): { sanDns: string[]; sanIps: string[]; errors: string[] } {
  const sanDns: string[] = []
  const sanIps: string[] = []
  const errors: string[] = []

  for (const raw of entries) {
    const trimmed = raw.trim()
    if (!trimmed) continue
    const res = validateSanEntry(trimmed)
    if (!res.valid) {
      errors.push(res.error ?? `格式错误: ${trimmed}`)
    } else if (res.type === 'ip') {
      if (!sanIps.includes(trimmed)) sanIps.push(trimmed)
    } else if (res.type === 'dns') {
      if (!sanDns.includes(trimmed)) sanDns.push(trimmed)
    }
  }

  return { sanDns, sanIps, errors }
}

export function getDefaultDays(profile: CertificateProfile): number {
  return PROFILES[profile]?.defaultDays ?? 365
}

export async function fetchKeyGenerationCapabilities(): Promise<KeyGenerationCapabilities | null> {
  try {
    return await request<KeyGenerationCapabilities>('/key-generation-capabilities')
  } catch {
    return null
  }
}

export async function submitCertificateWorkflow(
  projectId: string,
  payload: CertificateWorkflowRequest
): Promise<CertificateWorkflowResponse> {
  try {
    return await post<CertificateWorkflowResponse>(`/projects/${projectId}/certificate-workflows`, payload)
  } catch (err) {
    throw new Error(errorMessage(err))
  }
}
