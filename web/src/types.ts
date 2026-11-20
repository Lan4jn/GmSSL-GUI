export type Role = 'ADMIN' | 'USER'
export type ProjectRole = 'OWNER' | 'EDITOR' | 'VIEWER'
export interface User { id: string; username: string; role: Role; enabled?: boolean; createdAt?: string }
export interface Session { user: User; csrfToken: string }
export interface Project { id: string; name: string; description?: string; role: ProjectRole; createdAt: string }
export interface Member { userId: string; username: string; role: ProjectRole }
export type ParamType = 'BOOLEAN' | 'STRING' | 'INTEGER' | 'ENUM' | 'HEX' | 'SECRET' | 'INPUT_FILE' | 'OUTPUT_FILE'
export interface Parameter {
  name: string
  flag: string
  label: string
  type: ParamType
  required: boolean
  description: string
  defaultValue?: unknown
  options?: string[]
  min?: number
  max?: number
  repeatable?: boolean
  secret?: boolean
  allowKeyReference?: boolean
  allowedKeyKinds?: string[]
  advanced?: boolean
  preferred?: boolean
  recommendation?: string
  formatHint?: string
  credentialKeyParameter?: string
}
export interface Tool { id: string; command: string; title: string; category: string; description: string; parameters: Parameter[]; acceptsStdin: boolean; stdoutMediaType: string; stdoutFilename: string; sensitiveOutput: boolean; defaultTimeoutSeconds: number; maxTimeoutSeconds: number; adminOnly: boolean; stateful: boolean; verification: { status: string; evidence: unknown } }
export interface Catalog { provider: string; version: string; sourceCommit: string; categories: string[]; tools: Tool[]; coverage: Record<string, unknown> }
export interface Key {
  id: string
  projectId: string
  name: string
  algorithm: string
  keyKind: string
  encoding: string
  validationStatus: string
  usage?: string
  description?: string
  publicFingerprint?: string
  createdAt: string
  updatedAt: string
  stateful: boolean
  hasManagedPassphrase?: boolean
  generationProvider?: string
}
export interface ManagedFile {
  id: string
  name: string
  size: number
  mediaType: string
  createdAt: string
  temporary?: boolean
  hasManagedPassphrase?: boolean
  generationProvider?: string
}
export interface GenerationProvider {
  id: 'gmssl' | 'openssl'
  available: boolean
  version?: string
  reason?: string
  algorithms: string[]
}
export interface GenerationAlgorithm {
  id: string
  name?: string
  kind: string
  bits?: number[]
  curves?: string[]
  providers: string[]
}
export interface KeyGenerationCapabilities {
  providers: GenerationProvider[]
  algorithms: GenerationAlgorithm[]
}
export interface GenerateKeyRequest {
  provider: 'gmssl' | 'openssl'
  algorithm: string
  name?: string
  bits?: number
  curve?: string
  storage: 'MANAGED' | 'TEMPORARY'
  password?: string
}
export interface GenerateKeyResponse {
  provider: string
  algorithm: string
  storage: 'MANAGED' | 'TEMPORARY'
  reference?: string
  key?: Key
  publicKey?: Key
  temporaryFile?: ManagedFile
  temporaryPublicKeyFile?: ManagedFile
  valueHex?: string
  warnings: string[]
}
export interface RevealPassphraseResponse {
  passphrase?: string
}
export interface Artifact { id: string; name: string; size: number; mediaType: string; sensitive: boolean; downloadable?: boolean; promotable?: boolean; statefulPrivate?: boolean }
export interface Job { id: string; projectId: string; toolId: string; status: string; createdAt: string; startedAt?: string; finishedAt?: string; exitCode?: number; durationMs?: number; error?: string; stdoutPreview?: string; stderrPreview?: string; truncated: boolean; artifacts: Artifact[] }
export interface Audit { id: string; actor: string; action: string; resourceType: string; resourceId: string; outcome: string; createdAt: string }
export const categoryNames: Record<string,string> = { digest:'摘要',mac:'消息认证',symmetric:'对称密码',asymmetric:'非对称密码',kdf:'密钥派生',random:'随机数',pqc:'后量子密码',key:'密钥管理',certificate:'证书与 PKI',envelope:'数字信封',protocol:'网络协议',utility:'实用工具' }
export const statusNames: Record<string,string> = { QUEUED:'排队中',RUNNING:'运行中',SUCCEEDED:'已成功',FAILED:'执行失败',TIMED_OUT:'已超时',CANCELLED:'已取消',tested:'已测试',implemented:'已实现',unverified:'未验证',unavailable:'暂不可用',UNVERIFIED:'未验证',VALIDATED:'已验证' }

export type CertificateCategory =
  | 'ROOT_CA'
  | 'INTERMEDIATE_CA'
  | 'ISSUED_CERT'
  | 'SELF_SIGNED_END_ENTITY'
  | 'ORPHAN'
  | 'UNSUPPORTED'
  | 'ENGINE_PENDING'

export type CertificateValidityStatus = 'VALID' | 'EXPIRED' | 'NOT_YET_VALID' | 'UNKNOWN'

export type CsrMatchEvidence =
  | 'KEY_AND_SUBJECT_MATCH'
  | 'KEY_MATCH_DIFFERENT_SUBJECT'
  | 'AMBIGUOUS_MATCH'

export type CsrMatchKind =
  | 'KEY_AND_SUBJECT_MATCH'
  | 'KEY_MATCH_DIFFERENT_SUBJECT'
  | 'UNMATCHED'
  | 'INVALID_CSR'

export interface CertificateNode {
  id: string
  fingerprint?: string
  name: string
  category: CertificateCategory
  subjectCN: string
  issuerCN: string
  serialNumber?: string
  validBefore?: string
  validAfter?: string
  validityStatus: CertificateValidityStatus
  revocationStatus: 'UNCHECKED'
  isCa: boolean
  selectableAsIssuer: boolean
  parentRefs: string[]
  materialRefs?: string[]
  downloadRef?: string
  sourceFileRef?: string
  error?: string
  matchedCsrRefs?: string[]
  csrMatchEvidence?: CsrMatchEvidence
}

export interface CsrNode {
  id: string
  name: string
  subjectCN: string
  createdAt: string
  downloadRef?: string
  spkiFingerprint?: string
  matchedCertIds?: string[]
  matchKind?: CsrMatchKind
  ambiguous?: boolean
  error?: string
}

export interface BundleNode {
  id: string
  name: string
  containsCertIds: string[]
  downloadRef?: string
}

export interface CertificateTreeResponse {
  nodes: CertificateNode[]
  csrs: CsrNode[]
  bundles: BundleNode[]
}

export type StandardCertStatus = 'VALID' | 'REVOKED' | 'EXPIRED'

export interface StandardClientCertificate {
  id: string
  projectId: string
  requestId: string
  deviceLabel: string
  fingerprint: string
  serial: string
  expiresAt: number // epoch ms
  status: StandardCertStatus
  certificatePem: string
  chainPem?: string
}

export interface StandardCertPageResult {
  items: StandardClientCertificate[]
  total: number
}

export interface IssueStandardCertRequest {
  requestId: string
  csrPem: string
  deviceLabel: string
}

