import type { Session, KeyGenerationCapabilities, GenerateKeyRequest, GenerateKeyResponse, RevealPassphraseResponse, CertificateTreeResponse, StandardClientCertificate, StandardCertPageResult, IssueStandardCertRequest } from './types'
let csrfToken = ''
export const setCsrfToken = (token: string) => { csrfToken = token }
export class ApiError extends Error {
  constructor(public status: number, public code: string, message: string, public requestId?: string) { super(message); this.name = 'ApiError' }
}
export async function request<T>(path: string, init: RequestInit = {}): Promise<T> {
  const method = (init.method ?? 'GET').toUpperCase()
  const headers = new Headers(init.headers)
  if (init.body && !(init.body instanceof FormData)) headers.set('Content-Type', 'application/json')
  if (!['GET','HEAD'].includes(method) && path !== '/auth/login') headers.set('X-CSRF-Token', csrfToken)
  let response: Response
  try { response = await fetch(`/api/v1${path}`, { ...init, method, headers, credentials:'same-origin', cache:'no-store' }) }
  catch { throw new ApiError(0, 'NETWORK_ERROR', '连接服务失败，请检查网络和平台服务。') }
  if (!response.ok) {
    let data: {code?:string;message?:string;requestId?:string} = {}
    try { data = await response.json() } catch { /* A proxy may return a non-JSON error. */ }
    if (response.status === 401 && path !== '/auth/login') { setCsrfToken(''); window.dispatchEvent(new Event('session-expired')) }
    throw new ApiError(response.status, data.code ?? `HTTP_${response.status}`, data.message ?? `请求失败（HTTP ${response.status}）`, data.requestId)
  }
  if (response.status === 204) return undefined as T
  return response.json() as Promise<T>
}
export async function session(path: string, body?: unknown) { const s = await request<Session>(path, body ? {method:'POST',body:JSON.stringify(body)} : {}); setCsrfToken(s.csrfToken); return s }
export const post = <T>(path: string, body?: unknown) => request<T>(path, {method:'POST', ...(body === undefined ? {} : {body:JSON.stringify(body)})})
export async function download(path: string, filename: string) {
  const response = await fetch(`/api/v1${path}`, {credentials:'same-origin',cache:'no-store'})
  if (!response.ok) { let data: {message?: string;code?:string;requestId?:string} = {}; try { data = await response.json() } catch { /* No API JSON. */ }; throw new ApiError(response.status, data.code ?? 'DOWNLOAD_FAILED', data.message ?? '下载失败', data.requestId) }
  const blob = await response.blob(); const url = URL.createObjectURL(blob)
  const a = document.createElement('a'); a.href = url; a.download = filename; document.body.appendChild(a); a.click(); a.remove(); setTimeout(() => URL.revokeObjectURL(url), 1000)
}
export function errorMessage(error: unknown) { return error instanceof ApiError ? `${error.message}${error.requestId ? ` · 请求 ${error.requestId}` : ''}` : error instanceof Error ? error.message : '发生未知错误' }

export async function getKeyGenCapabilities(): Promise<KeyGenerationCapabilities> {
  return request<KeyGenerationCapabilities>('/key-generation-capabilities')
}

export async function generateKey(projectId: string, payload: GenerateKeyRequest): Promise<GenerateKeyResponse> {
  return post<GenerateKeyResponse>(`/projects/${projectId}/keys/generate`, payload)
}

export async function revealKeyPassphrase(projectId: string, keyId: string): Promise<RevealPassphraseResponse> {
  return post<RevealPassphraseResponse>(`/projects/${projectId}/keys/${keyId}/reveal-passphrase`)
}

export async function getProjectCertificates(projectId: string): Promise<CertificateTreeResponse> {
  return request<CertificateTreeResponse>(`/projects/${projectId}/certificates`)
}

export async function listStandardCertificates(
  projectId: string,
  params: { fingerprint?: string; page?: number; size?: number } = {}
): Promise<StandardCertPageResult> {
  const query = new URLSearchParams()
  if (params.fingerprint !== undefined && params.fingerprint !== '') {
    query.set('fingerprint', params.fingerprint)
  }
  if (params.page !== undefined) {
    query.set('page', String(params.page))
  }
  if (params.size !== undefined) {
    query.set('size', String(params.size))
  }
  const qs = query.toString()
  return request<StandardCertPageResult>(`/projects/${projectId}/standard-client-certificates${qs ? `?${qs}` : ''}`)
}

export async function issueStandardCertificate(
  projectId: string,
  payload: IssueStandardCertRequest
): Promise<StandardClientCertificate> {
  return post<StandardClientCertificate>(`/projects/${projectId}/standard-client-certificates`, payload)
}

export async function getStandardCertificate(
  projectId: string,
  id: string
): Promise<StandardClientCertificate> {
  return request<StandardClientCertificate>(`/projects/${projectId}/standard-client-certificates/${id}`)
}

export async function revokeStandardCertificate(
  projectId: string,
  id: string
): Promise<StandardClientCertificate> {
  return post<StandardClientCertificate>(`/projects/${projectId}/standard-client-certificates/${id}/revoke`)
}
