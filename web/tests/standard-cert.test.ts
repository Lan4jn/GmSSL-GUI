import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import {
  setCsrfToken,
  listStandardCertificates,
  issueStandardCertificate,
  getStandardCertificate,
  revokeStandardCertificate
} from '../src/api'
import type { StandardClientCertificate } from '../src/types'
import StandardCertManager from '../src/components/StandardCertManager.vue'

const dummyCert: StandardClientCertificate = {
  id: 'cert-1',
  projectId: 'p-1',
  requestId: 'req-001',
  deviceLabel: 'Device-A',
  fingerprint: 'AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00',
  serial: '202611200001',
  expiresAt: Date.now() + 86400000 * 365, // 1 year later
  status: 'VALID',
  certificatePem: '-----BEGIN CERTIFICATE-----\nMIIB...fake-cert\n-----END CERTIFICATE-----',
  chainPem: '-----BEGIN CERTIFICATE-----\nMIIB...fake-ca-chain\n-----END CERTIFICATE-----'
}

const expiredCert: StandardClientCertificate = {
  id: 'cert-expired',
  projectId: 'p-1',
  requestId: 'req-002',
  deviceLabel: 'Device-Old',
  fingerprint: '11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00',
  serial: '202511200001',
  expiresAt: Date.now() - 3600000, // expired 1 hour ago
  status: 'EXPIRED',
  certificatePem: '-----BEGIN CERTIFICATE-----\nMIIB...fake-expired\n-----END CERTIFICATE-----'
}

describe('Standard Client Certificate API Contract', () => {
  beforeEach(() => {
    setCsrfToken('csrf-token-123')
    vi.restoreAllMocks()
  })

  it('listStandardCertificates requests correct URL with credentials and query params', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [dummyCert], total: 1 })))
    vi.stubGlobal('fetch', fetch)

    const result = await listStandardCertificates('p-1', { fingerprint: 'AA:BB', page: 0, size: 50 })
    expect(result.items).toHaveLength(1)
    expect(result.total).toBe(1)
    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0]
    expect(url).toContain('/api/v1/projects/p-1/standard-client-certificates?fingerprint=AA%3ABB&page=0&size=50')
    expect(init.credentials).toBe('same-origin')
    expect(init.headers.has('X-CSRF-Token')).toBe(false) // GET does not need CSRF
  })

  it('issueStandardCertificate sends POST with X-CSRF-Token and json body', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(dummyCert)))
    vi.stubGlobal('fetch', fetch)

    const payload = {
      requestId: 'req-001',
      csrPem: '-----BEGIN CERTIFICATE REQUEST-----\nMIIB...fake-csr\n-----END CERTIFICATE REQUEST-----',
      deviceLabel: 'Device-A'
    }
    const result = await issueStandardCertificate('p-1', payload)
    expect(result.id).toBe('cert-1')
    expect(fetch).toHaveBeenCalledTimes(1)
    const [url, init] = fetch.mock.calls[0]
    expect(url).toContain('/api/v1/projects/p-1/standard-client-certificates')
    expect(init.method).toBe('POST')
    expect(init.credentials).toBe('same-origin')
    expect(init.headers.get('X-CSRF-Token')).toBe('csrf-token-123')
    expect(init.headers.get('Content-Type')).toBe('application/json')
    expect(JSON.parse(init.body)).toEqual(payload)
  })

  it('getStandardCertificate requests single certificate by id', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(dummyCert)))
    vi.stubGlobal('fetch', fetch)

    const result = await getStandardCertificate('p-1', 'cert-1')
    expect(result.id).toBe('cert-1')
    expect(fetch.mock.calls[0][0]).toContain('/api/v1/projects/p-1/standard-client-certificates/cert-1')
  })

  it('revokeStandardCertificate sends POST with CSRF to revoke endpoint', async () => {
    const revoked = { ...dummyCert, status: 'REVOKED' as const }
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify(revoked)))
    vi.stubGlobal('fetch', fetch)

    const result = await revokeStandardCertificate('p-1', 'cert-1')
    expect(result.status).toBe('REVOKED')
    const [url, init] = fetch.mock.calls[0]
    expect(url).toContain('/api/v1/projects/p-1/standard-client-certificates/cert-1/revoke')
    expect(init.method).toBe('POST')
    expect(init.headers.get('X-CSRF-Token')).toBe('csrf-token-123')
  })
})

describe('StandardCertManager UI Component', () => {
  const mountedWrappers: ReturnType<typeof mount>[] = []
  afterEach(() => {
    mountedWrappers.forEach(w => w.unmount())
    mountedWrappers.length = 0
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('loads and displays standard client certificates for the selected project', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [dummyCert, expiredCert], total: 2 })))
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    expect(wrapper.text()).toContain('Device-A')
    expect(wrapper.text()).toContain('AA:BB:CC:DD:EE:FF:11:22:33:44:55:66:77:88:99:00')
    expect(wrapper.text()).toContain('正常')
    expect(wrapper.text()).toContain('Device-Old')
    expect(wrapper.text()).toContain('已过期')
  })

  it('strictly rejects private key and warns user when pasting private key instead of CSR', async () => {
    const fetch = vi.fn()
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    const deviceInput = wrapper.get('input[data-test="device-label-input"]')
    await deviceInput.setValue('Device-Secret')

    const csrInput = wrapper.get('textarea[data-test="csr-pem-input"]')
    await csrInput.setValue('-----BEGIN EC PRIVATE KEY-----\nMHcCAQEEI...FAKE_PRIVATE_KEY\n-----END EC PRIVATE KEY-----')

    const submitBtn = wrapper.get('button[data-test="submit-issue-btn"]')
    await submitBtn.trigger('click')
    await flushPromises()

    // Must be blocked before sending any network request
    const postCalls = fetch.mock.calls.filter(c => c[1]?.method === 'POST')
    expect(postCalls).toHaveLength(0)
    expect(wrapper.text()).toContain('严禁输入私钥')
  })

  it('strictly validates CSR format and rejects empty or invalid PEM', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [], total: 0 })))
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    await wrapper.get('input[data-test="device-label-input"]').setValue('Device-Test')
    const csrInput = wrapper.get('textarea[data-test="csr-pem-input"]')
    await csrInput.setValue('-----BEGIN NEW CERTIFICATE REQUEST-----\nYWFh\n-----END NEW CERTIFICATE REQUEST-----')

    const submitBtn = wrapper.get('button[data-test="submit-issue-btn"]')
    await submitBtn.trigger('click')
    await flushPromises()

    const postCalls = fetch.mock.calls.filter(c => c[1]?.method === 'POST')
    expect(postCalls).toHaveLength(0)
    expect(wrapper.text()).toContain('无效的 CSR')
  })

  it('reuses requestId upon network failure during retry, and generates new requestId after success', async () => {
    let callCount = 0
    const capturedBodies: any[] = []

    const fetch = vi.fn(async (url: string, init?: RequestInit) => {
      if (url.includes('standard-client-certificates') && init?.method === 'POST') {
        callCount++
        capturedBodies.push(JSON.parse(init.body as string))
        if (callCount === 1) {
          // First attempt fails with network error
          throw new Error('Connection reset')
        }
        // Second attempt succeeds
        return new Response(JSON.stringify({ ...dummyCert, id: 'cert-new', requestId: capturedBodies[0].requestId }))
      }
      return new Response(JSON.stringify({ items: [], total: 0 }))
    })
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    await wrapper.get('input[data-test="device-label-input"]').setValue('Device-Retry')
    await wrapper.get('textarea[data-test="csr-pem-input"]').setValue('-----BEGIN CERTIFICATE REQUEST-----\nYWFh\n-----END CERTIFICATE REQUEST-----')

    // First attempt -> fails
    await wrapper.get('button[data-test="submit-issue-btn"]').trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('失败')
    const firstReqId = capturedBodies[0].requestId
    expect(firstReqId).toBeTruthy()

    // User clicks submit again to retry -> MUST reuse the same requestId
    await wrapper.get('button[data-test="submit-issue-btn"]').trigger('click')
    await flushPromises()

    expect(capturedBodies).toHaveLength(2)
    expect(capturedBodies[1].requestId).toBe(firstReqId) // Reused!
    expect(wrapper.text()).toContain('签发成功')
  })

  it('prevents double-clicking by disabling submit button and debouncing', async () => {
    let resolvePromise: (value: any) => void
    const pendingPromise = new Promise(resolve => { resolvePromise = resolve })

    const fetch = vi.fn(async (_url: string, init?: RequestInit) => {
      if (init?.method === 'POST') {
        await pendingPromise
        return new Response(JSON.stringify(dummyCert))
      }
      return new Response(JSON.stringify({ items: [], total: 0 }))
    })
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    await wrapper.get('input[data-test="device-label-input"]').setValue('Device-Double')
    await wrapper.get('textarea[data-test="csr-pem-input"]').setValue('-----BEGIN CERTIFICATE REQUEST-----\nYWFh\n-----END CERTIFICATE REQUEST-----')

    const btn = wrapper.get('button[data-test="submit-issue-btn"]')
    // Trigger twice rapidly
    btn.trigger('click')
    btn.trigger('click')
    await wrapper.vm.$nextTick()

    expect(btn.attributes('disabled')).toBeDefined()
    resolvePromise!(null)
    await flushPromises()

    // Only one POST call was made
    const postCalls = fetch.mock.calls.filter(call => call[1]?.method === 'POST')
    expect(postCalls).toHaveLength(1)
  })

  it('supports copying fingerprint and certificate with notification', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [dummyCert], total: 1 })))
    vi.stubGlobal('fetch', fetch)

    const writeText = vi.fn().mockResolvedValue(undefined)
    vi.stubGlobal('navigator', {
      clipboard: { writeText }
    })

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    // Click copy fingerprint
    const copyFpBtn = wrapper.get('button[data-test="copy-fingerprint-btn"]')
    await copyFpBtn.trigger('click')
    await flushPromises()

    expect(writeText).toHaveBeenCalledWith(dummyCert.fingerprint)
    expect(wrapper.text()).toContain('已复制')

    // Click copy certificate PEM
    const copyCertBtn = wrapper.get('button[data-test="copy-cert-btn"]')
    await copyCertBtn.trigger('click')
    await flushPromises()

    expect(writeText).toHaveBeenCalledWith(dummyCert.certificatePem)
  })

  it('supports downloading certificate and chain', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [dummyCert], total: 1 })))
    vi.stubGlobal('fetch', fetch)

    const createObjectURL = vi.fn().mockReturnValue('blob:http://localhost/cert-blob')
    const revokeObjectURL = vi.fn()
    vi.stubGlobal('URL', { createObjectURL, revokeObjectURL })

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    const downloadCertBtn = wrapper.get('button[data-test="download-cert-btn"]')
    await downloadCertBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalled()

    const downloadChainBtn = wrapper.get('button[data-test="download-chain-btn"]')
    await downloadChainBtn.trigger('click')
    expect(createObjectURL).toHaveBeenCalledTimes(2)
  })

  it('requires explicit confirmation before revoking and clearly states "吊销≠本地解绑"', async () => {
    let revoked = false
    const fetch = vi.fn(async (url: string, _init?: RequestInit) => {
      if (url.includes('/revoke')) {
        revoked = true
        return new Response(JSON.stringify({ ...dummyCert, status: 'REVOKED' }))
      }
      return new Response(JSON.stringify({ items: [dummyCert], total: 1 }))
    })
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    // Click revoke button to open confirmation dialog
    const revokeBtn = wrapper.get('button[data-test="open-revoke-btn"]')
    await revokeBtn.trigger('click')
    await flushPromises()

    // Dialog must clearly highlight "吊销≠本地解绑"
    expect(wrapper.text()).toContain('吊销≠本地解绑')
    expect(revoked).toBe(false)

    // Confirm revoke
    const confirmRevokeBtn = wrapper.get('button[data-test="confirm-revoke-btn"]')
    await confirmRevokeBtn.trigger('click')
    await flushPromises()

    expect(revoked).toBe(true)
    expect(wrapper.text()).toContain('已吊销')
  })

  it('shows clear error and retry action when server is down or returns network error', async () => {
    const fetch = vi.fn().mockRejectedValue(new Error('Failed to fetch'))
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    expect(wrapper.text()).toContain('服务异常或已停服')
    const retryBtn = wrapper.find('button[data-test="retry-load-btn"]')
    expect(retryBtn.exists()).toBe(true)

    // When server comes back up
    fetch.mockResolvedValueOnce(new Response(JSON.stringify({ items: [dummyCert], total: 1 })))
    await retryBtn.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('Device-A')
  })

  it('supports searching by fingerprint and pagination', async () => {
    const fetch = vi.fn().mockResolvedValue(new Response(JSON.stringify({ items: [dummyCert], total: 100 })))
    vi.stubGlobal('fetch', fetch)

    const wrapper = mount(StandardCertManager, {
      props: {
        projectId: 'p-1',
        isAdmin: true
      }
    })
    mountedWrappers.push(wrapper)
    await flushPromises()

    const searchInput = wrapper.get('input[data-test="search-fingerprint-input"]')
    await searchInput.setValue('AA:BB:CC')
    await wrapper.get('button[data-test="search-btn"]').trigger('click')
    await flushPromises()

    const lastCall = fetch.mock.calls[fetch.mock.calls.length - 1]
    expect(lastCall[0]).toContain('fingerprint=AA%3ABB%3ACC')
  })
})

describe('App Workspace Integration for Standard Client Certificates', () => {
  const mountedWrappers: ReturnType<typeof mount>[] = []
  afterEach(() => {
    mountedWrappers.forEach(w => w.unmount())
    mountedWrappers.length = 0
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('renders "客户端证书" in sidebar for ADMIN users and opens StandardCertManager view', async () => {
    const project = { id: 'proj-1', name: '国密专用项目', role: 'OWNER', createdAt: '2026-01-01T00:00:00Z' }
    const catalog = { provider: 'gmssl', version: 'test-build', sourceCommit: 'abc', categories: ['certificate'], coverage: { tested: 1 }, tools: [] }
    const responses: Record<string, unknown> = {
      '/auth/me': { user: { id: 'admin-1', username: 'super-admin', role: 'ADMIN' }, csrfToken: 'admin-csrf' },
      '/projects': [project],
      '/capabilities': catalog,
      [`/projects/${project.id}/keys`]: [],
      [`/projects/${project.id}/files`]: [],
      [`/projects/${project.id}/jobs`]: [],
      [`/projects/${project.id}/standard-client-certificates?page=0&size=50`]: { items: [dummyCert], total: 1 }
    }
    vi.stubGlobal('fetch', vi.fn(async (path: string) => new Response(JSON.stringify(responses[path.replace('/api/v1', '')] ?? []))))

    const { default: App } = await import('../src/App.vue')
    const wrapper = mount(App)
    mountedWrappers.push(wrapper)
    await flushPromises()

    // Switch to advanced mode to view sidebar navigation
    await wrapper.findAll('.mode-switcher button').find(b => b.text().includes('高级模式'))!.trigger('click')
    await flushPromises()

    const navButtons = wrapper.findAll('nav button')
    const certNavBtn = navButtons.find(b => b.text().includes('客户端证书'))
    expect(certNavBtn).toBeDefined()

    // Click navigation item
    await certNavBtn!.trigger('click')
    await flushPromises()

    expect(wrapper.text()).toContain('标准客户端证书')
    expect(wrapper.text()).toContain('Device-A')
    expect(wrapper.text()).toContain('快速签发客户端证书')
  })

  it('hides "客户端证书" navigation completely for regular non-ADMIN users', async () => {
    const project = { id: 'proj-1', name: '国密专用项目', role: 'VIEWER', createdAt: '2026-01-01T00:00:00Z' }
    const responses: Record<string, unknown> = {
      '/auth/me': { user: { id: 'user-1', username: 'normal-user', role: 'USER' }, csrfToken: 'user-csrf' },
      '/projects': [project],
      '/capabilities': { provider: 'gmssl', version: 'test-build', sourceCommit: 'abc', categories: [], coverage: { tested: 1 }, tools: [] },
      [`/projects/${project.id}/keys`]: [],
      [`/projects/${project.id}/files`]: [],
      [`/projects/${project.id}/jobs`]: []
    }
    vi.stubGlobal('fetch', vi.fn(async (path: string) => new Response(JSON.stringify(responses[path.replace('/api/v1', '')] ?? []))))

    const { default: App } = await import('../src/App.vue')
    const wrapper = mount(App)
    mountedWrappers.push(wrapper)
    await flushPromises()

    await wrapper.findAll('.mode-switcher button').find(b => b.text().includes('高级模式'))!.trigger('click')
    await flushPromises()

    const nav = wrapper.get('nav').text()
    expect(nav).not.toContain('客户端证书')
  })
})
