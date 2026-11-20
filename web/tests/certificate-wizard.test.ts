import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import CertificateWizard from '../src/components/CertificateWizard.vue'
import {
  getDefaultDays,
  validateSanEntry,
  parseSanEntries,
  submitCertificateWorkflow,
  type CertificateWorkflowResponse
} from '../src/certificate-wizard'
import type { Key, ManagedFile, KeyGenerationCapabilities, CertificateTreeResponse } from '../src/types'

describe('certificate-wizard helpers & strict RFC validation', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('provides correct default validity days for all profiles', () => {
    expect(getDefaultDays('ROOT_CA')).toBe(3650)
    expect(getDefaultDays('INTERMEDIATE_CA')).toBe(1825)
    expect(getDefaultDays('SELF_SIGNED')).toBe(365)
    expect(getDefaultDays('CSR')).toBe(365)
    expect(getDefaultDays('CA_SIGN')).toBe(365)
    expect(getDefaultDays('TLCP')).toBe(365)
    expect(getDefaultDays('QUICK_ISSUE')).toBe(365)
  })

  it('validates strictly valid SAN entries (IPv4, IPv6, DNS, wildcard, internal hostnames, punycode)', () => {
    // DNS multi-label
    expect(validateSanEntry('example.com')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('*.example.com')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('api.service.sub.example.cn')).toEqual({ type: 'dns', valid: true })

    // Internal single-label hostnames (localhost, labnode, node-1)
    expect(validateSanEntry('localhost')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('labnode')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('node-1')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('*.labnode')).toEqual({ type: 'dns', valid: true })

    // IDNA ASCII Punycode TLD
    expect(validateSanEntry('example.xn--fiqs8s')).toEqual({ type: 'dns', valid: true })
    expect(validateSanEntry('xn--fiqs8s.cn')).toEqual({ type: 'dns', valid: true })

    // IPv4
    expect(validateSanEntry('192.168.1.1')).toEqual({ type: 'ip', valid: true })
    expect(validateSanEntry('10.0.0.1')).toEqual({ type: 'ip', valid: true })
    expect(validateSanEntry('0.0.0.0')).toEqual({ type: 'ip', valid: true })
    expect(validateSanEntry('255.255.255.255')).toEqual({ type: 'ip', valid: true })

    // IPv6
    expect(validateSanEntry('::1')).toEqual({ type: 'ip', valid: true })
    expect(validateSanEntry('2001:db8::1')).toEqual({ type: 'ip', valid: true })
    expect(validateSanEntry('fe80::1ff:fe23:4567:890a')).toEqual({ type: 'ip', valid: true })
  })

  it('strictly rejects invalid / loose SAN entries (negative RFC test cases)', () => {
    // Empty & whitespace
    expect(validateSanEntry('').valid).toBe(false)
    expect(validateSanEntry('   ').valid).toBe(false)

    // URI, schemes, paths, spaces, ports
    expect(validateSanEntry('https://x').valid).toBe(false)
    expect(validateSanEntry('http://example.com').valid).toBe(false)
    expect(validateSanEntry('example.com/path').valid).toBe(false)
    expect(validateSanEntry('example.com:443').valid).toBe(false)
    expect(validateSanEntry('bad domain with space').valid).toBe(false)

    // Invalid IPv4
    expect(validateSanEntry('999.999.999.999').valid).toBe(false)
    expect(validateSanEntry('01.1.1.1').valid).toBe(false) // leading zero rejected
    expect(validateSanEntry('192.168.1').valid).toBe(false)
    expect(validateSanEntry('192.168.1.1.1').valid).toBe(false)

    // Invalid IPv6
    expect(validateSanEntry(':::').valid).toBe(false)
    expect(validateSanEntry('1:2').valid).toBe(false)
    expect(validateSanEntry('[::1]').valid).toBe(false)

    // Pure numeric single-label or TLD
    expect(validateSanEntry('123').valid).toBe(false)
    expect(validateSanEntry('example.123').valid).toBe(false)

    // Invalid DNS / Label / Wildcard
    expect(validateSanEntry('-bad-.com').valid).toBe(false)
    expect(validateSanEntry('bad-.com').valid).toBe(false)
    expect(validateSanEntry('-bad.com').valid).toBe(false)
    expect(validateSanEntry('*.').valid).toBe(false)
    expect(validateSanEntry('*').valid).toBe(false)
    expect(validateSanEntry('foo.*.com').valid).toBe(false)
    expect(validateSanEntry('*.example..com').valid).toBe(false)
  })

  it('parses multi-line and comma-separated SAN list and separates DNS vs IP correctly', () => {
    const list = ['api.example.com', '127.0.0.1', '::1', 'labnode', 'example.xn--fiqs8s']
    const res = parseSanEntries(list)
    expect(res.errors).toHaveLength(0)
    expect(res.sanDns).toEqual(['api.example.com', 'labnode', 'example.xn--fiqs8s'])
    expect(res.sanIps).toEqual(['127.0.0.1', '::1'])
  })

  it('posts workflow request via submitCertificateWorkflow to exact API route', async () => {
    const mockRes: CertificateWorkflowResponse = {
      workflowId: 'wf-123',
      status: 'SUCCEEDED',
      stages: [{ name: 'generate_key', status: 'SUCCEEDED' }, { name: 'generate_cert', status: 'SUCCEEDED' }],
      keys: [],
      files: [],
      warnings: []
    }

    const fetchSpy = vi.fn(async () => new Response(JSON.stringify(mockRes), { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)

    const result = await submitCertificateWorkflow('proj-abc', {
      profile: 'SELF_SIGNED',
      name: 'Test Cert',
      subject: { CN: 'test.com' },
      days: 365
    })

    expect(result.workflowId).toBe('wf-123')
    expect(result.status).toBe('SUCCEEDED')
    expect(fetchSpy).toHaveBeenCalledWith(
      '/api/v1/projects/proj-abc/certificate-workflows',
      expect.objectContaining({ method: 'POST' })
    )
  })
})

describe('CertificateWizard.vue component', () => {
  const dummyKeys: Key[] = [
    {
      id: 'k1',
      projectId: 'proj-1',
      name: 'Managed Key',
      algorithm: 'SM2',
      keyKind: 'PRIVATE_KEY',
      encoding: 'PEM',
      validationStatus: 'VALIDATED',
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
      stateful: false,
      hasManagedPassphrase: true
    },
    {
      id: 'k2',
      projectId: 'proj-1',
      name: 'Unmanaged Key',
      algorithm: 'SM2',
      keyKind: 'PRIVATE_KEY',
      encoding: 'PEM',
      validationStatus: 'VALIDATED',
      createdAt: '2026-01-01T00:00:00Z',
      updatedAt: '2026-01-01T00:00:00Z',
      stateful: false,
      hasManagedPassphrase: false
    }
  ]

  const dummyFiles: ManagedFile[] = [
    {
      id: 'f1',
      name: 'root_ca.crt',
      size: 1024,
      mediaType: 'application/x-x509-ca-cert',
      createdAt: '2026-01-01T00:00:00Z'
    },
    {
      id: 'f2',
      name: 'app.csr',
      size: 512,
      mediaType: 'application/pkcs10',
      createdAt: '2026-01-01T00:00:00Z'
    },
    {
      id: 'f3',
      name: 'data.bin',
      size: 2048,
      mediaType: 'application/octet-stream',
      createdAt: '2026-01-01T00:00:00Z'
    }
  ]

  const mockCapabilities: KeyGenerationCapabilities = {
    providers: [
      { id: 'gmssl', available: true, algorithms: ['SM4', 'SM2'] },
      { id: 'openssl', available: false, reason: 'OpenSSL CLI not installed', algorithms: [] }
    ],
    algorithms: []
  }

  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('renders profile options (including QUICK_ISSUE) and defaults to SELF_SIGNED with 365 days', () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    const cards = wrapper.findAll('.profile-card')
    expect(cards).toHaveLength(7)
    expect(wrapper.get('.profile-card.selected').text()).toContain('单证自签名证书')
    expect(wrapper.text()).toContain('服务器证书 (SERVER)')
  })

  it('filters available CA certificates strictly by .crt/.pem/.cer and excludes non-cert files', async () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    // Advance to INTERMEDIATE_CA step 3
    const radio = wrapper.findAll('input[name="cert-profile"]').find(i => (i.element as HTMLInputElement).value === 'INTERMEDIATE_CA')!
    await radio.setValue(true)
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    // Expect f1 (root_ca.crt) present in issuer cert dropdown, but f3 (data.bin) excluded
    const options = wrapper.findAll('#issuer-cert option').map(o => o.text())
    expect(options.some(t => t.includes('root_ca.crt'))).toBe(true)
    expect(options.some(t => t.includes('data.bin'))).toBe(false)
  })

  it('handles provider fail-hard without silent switching when user selects unavailable OpenSSL', async () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    // Advance to Step 3
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('provider-test.com')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    // Initially gmssl is selected
    const select = wrapper.get('.provider-field select')
    expect((select.element as HTMLSelectElement).value).toBe('gmssl')

    // User explicitly selects openssl (which is unavailable)
    await select.setValue('openssl')

    // Expect explicit error alert shown and provider is NOT silently reverted to gmssl
    expect(wrapper.find('.provider-error-alert').exists()).toBe(true)
    expect(wrapper.find('.provider-error-alert').text()).toContain('系统严禁静默替换引擎进行冒充')
    expect((select.element as HTMLSelectElement).value).toBe('openssl')

    // Expect Next button to be disabled
    const nextBtn = wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!
    expect(nextBtn.attributes('disabled')).toBeDefined()
  })

  it.each(['SELF_SIGNED', 'CSR'])('shows real DNS and IP SAN support for %s in input and confirmation', async (profile) => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    await wrapper.get(`input[name="cert-profile"][value="${profile}"]`).setValue(true)
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('example.com')
    await wrapper.get('#san-input').setValue('example.com,192.168.1.100,2001:db8::1')
    expect(wrapper.get('.ip-san-notice').text()).toContain('支持 DNS、IPv4 和 IPv6 SAN 扩展')
    expect(wrapper.get('.ip-san-notice').text()).toContain('证书与 CSR')

    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    expect(wrapper.get('.confirm-summary .ip-san-notice').text()).toContain('支持 DNS、IPv4 和 IPv6 SAN 扩展')
    expect(wrapper.get('.confirm-summary').text()).toContain('2001:db8::1')
  })

  it.each(['证书', '_certificate', '.certificate', '-certificate', '../cert', '9-valid.cert', 'a'.repeat(120), '   '])('submits an ASCII filename-safe name for %j', async (name) => {
    const fetchSpy = vi.fn(async (_url: RequestInfo | URL, _init?: RequestInit) => new Response(JSON.stringify({ workflowId: 'wf-name', status: 'SUCCEEDED', stages: [] }), { status: 200 }))
    vi.stubGlobal('fetch', fetchSpy)
    const wrapper = mount(CertificateWizard, {
      props: { projectId: 'proj-1', capabilities: mockCapabilities }
    })
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('localhost')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#cert-name').setValue(name)
    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()
    const requestInit = fetchSpy.mock.calls[0]?.[1] as RequestInit
    const payload = JSON.parse(String(requestInit.body))
    expect(payload.name).toMatch(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,79}$/)
    expect(payload.name + '_cert.pem').toMatch(/^[A-Za-z0-9][A-Za-z0-9_.-]{0,119}$/)
    if (name === '9-valid.cert') expect(payload.name).toBe(name)
  })

  it('renders backend execution warnings prominently on completion', async () => {
    const mockResWithWarnings: CertificateWorkflowResponse = {
      workflowId: 'wf-warn',
      status: 'SUCCEEDED',
      stages: [{ name: 'generate_key', status: 'SUCCEEDED' }, { name: 'generate_cert', status: 'SUCCEEDED' }],
      keys: [],
      files: [],
      warnings: ['Certificate chain validation requires the deployment trust store']
    }

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(mockResWithWarnings), { status: 200 })))

    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    // Advance to Step 4 and submit
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('example.com')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()

    expect(wrapper.find('.warnings-container').exists()).toBe(true)
    expect(wrapper.find('.warnings-container').text()).toContain('系统执行告警与提示')
    expect(wrapper.find('.warnings-container').text()).toContain('Certificate chain validation requires the deployment trust store')
  })

  it('maps unmanaged private key password into payload.keyPassword', async () => {
    let capturedPayload: any = null
    vi.stubGlobal('fetch', vi.fn(async (_url, opts) => {
      capturedPayload = JSON.parse(opts.body)
      return new Response(JSON.stringify({ workflowId: 'wf-keypass', status: 'SUCCEEDED', stages: [] }), { status: 200 })
    }))

    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    // Step 1 -> Next to Step 2
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('api.local')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    // Step 3: Choose EXISTING unmanaged key k2
    const radio = wrapper.findAll('input[type="radio"]').find(r => (r.element as HTMLInputElement).value === 'EXISTING')!
    await radio.setValue(true)
    await wrapper.get('#existing-key').setValue('key:k2')

    // Input password
    await wrapper.get('#key-pass').setValue('secret1234')

    // Advance to Step 4 and submit
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()

    expect(capturedPayload.keyRef).toBe('key:k2')
    expect(capturedPayload.keyPassword).toBe('secret1234')
  })

  it('allows CA_SIGN to proceed without entering CN and shows CSR subject reuse notice', async () => {
    let capturedPayload: any = null
    vi.stubGlobal('fetch', vi.fn(async (_url, opts) => {
      capturedPayload = JSON.parse(opts.body)
      return new Response(JSON.stringify({ workflowId: 'wf-casign', status: 'SUCCEEDED', stages: [] }), { status: 200 })
    }))

    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities
      }
    })

    // Profile: CA_SIGN
    const radio = wrapper.findAll('input[name="cert-profile"]').find(i => (i.element as HTMLInputElement).value === 'CA_SIGN')!
    await radio.setValue(true)

    // Step 1 -> Step 2
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    expect(wrapper.text()).toContain('CA 签发将严格复用 CSR 证书请求文件中已签名的主体标识')

    // Step 2 allows Next without CN input
    const nextBtn = wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!
    expect(nextBtn.attributes('disabled')).toBeUndefined()
    await nextBtn.trigger('click')

    // Step 3: Fill CSR and Issuer
    await wrapper.get('#csr-file').setValue('file:f2')
    await wrapper.get('#issuer-cert').setValue('file:f1')
    await wrapper.get('#issuer-key').setValue('key:k1')

    // Step 3 -> Step 4 -> Submit
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()

    expect(capturedPayload.profile).toBe('CA_SIGN')
    expect(capturedPayload.csrRef).toBe('file:f2')
    expect(capturedPayload.subject).toBeUndefined()
  })

  it('notifies parent on partial failure when partial materials were generated', async () => {
    const mockFailure: CertificateWorkflowResponse = {
      workflowId: 'wf-partial-fail',
      status: 'FAILED',
      stages: [
        { name: 'generate_key', status: 'SUCCEEDED', jobId: 'job-1' },
        { name: 'sign_cert', status: 'FAILED', jobId: 'job-2' }
      ],
      keys: [{
        id: 'k-partial',
        projectId: 'proj-1',
        name: 'partial.key',
        algorithm: 'SM2',
        keyKind: 'PRIVATE_KEY',
        encoding: 'PEM',
        validationStatus: 'VALIDATED',
        createdAt: '2026-01-01T00:00:00Z',
        updatedAt: '2026-01-01T00:00:00Z',
        stateful: false
      }],
      files: [],
      error: 'CA 私钥无法解密',
      warnings: []
    }

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(mockFailure), { status: 200 })))

    const wrapper = mount(CertificateWizard, {
      props: { projectId: 'proj-1', capabilities: mockCapabilities }
    })

    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('fail.site')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('中断前已成功生成的材料（私钥或中间证书）已安全保存在项目中')
    expect(wrapper.text()).toContain('保留并查看已生成材料')

    // Click "保留并查看已生成材料" button
    await wrapper.findAll('.wizard-actions button').find(b => b.text().includes('保留并查看已生成材料'))!.trigger('click')
    expect(wrapper.emitted('complete')?.[0]?.[0]).toEqual(mockFailure)
  })

  it('emits close event when close button is clicked without materials', async () => {
    const wrapper = mount(CertificateWizard, {
      props: { projectId: 'proj-1', capabilities: mockCapabilities }
    })

    await wrapper.get('.wizard-header .icon-button').trigger('click')
    expect(wrapper.emitted('close')).toBeTruthy()
  })

  it('displays downloadable certificates, CSRs, and CA chains directly on success, with separate sensitive private key', async () => {
    const mockSuccess: CertificateWorkflowResponse = {
      workflowId: 'wf-cert-download-test',
      status: 'SUCCEEDED',
      stages: [
        { name: 'generate_key', status: 'SUCCEEDED' },
        { name: 'issue_cert', status: 'SUCCEEDED' }
      ],
      keys: [
        {
          id: 'k-priv-1',
          projectId: 'proj-1',
          name: 'server.key',
          algorithm: 'SM2',
          keyKind: 'PRIVATE_KEY',
          encoding: 'PEM',
          validationStatus: 'VALIDATED',
          createdAt: '2026-01-01T00:00:00Z',
          updatedAt: '2026-01-01T00:00:00Z',
          stateful: false
        }
      ],
      files: [
        {
          id: 'f-cert-1',
          name: 'server_cert.pem',
          size: 1024,
          mediaType: 'application/x-pem-file',
          createdAt: '2026-01-01T00:00:00Z'
        },
        {
          id: 'f-chain-1',
          name: 'server_chain.pem',
          size: 2048,
          mediaType: 'application/x-pem-file',
          createdAt: '2026-01-01T00:00:00Z'
        },
        {
          id: 'f-tlcp-keys',
          name: 'server_tlcp_keys.pem',
          size: 1500,
          mediaType: 'application/x-pem-file',
          createdAt: '2026-01-01T00:00:00Z'
        }
      ]
    }

    vi.stubGlobal('fetch', vi.fn(async () => new Response(JSON.stringify(mockSuccess), { status: 200 })))

    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        capabilities: mockCapabilities
      }
    })

    // Advance to step 4 and submit
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('test.download')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('form.step-form').trigger('submit')
    await flushPromises()

    expect(wrapper.text()).toContain('证书签发成功！')

    // Cert files must have direct download buttons
    const downloadBtns = wrapper.findAll('button.download-btn')
    expect(downloadBtns.length).toBeGreaterThanOrEqual(2)

    // Check separation: server_tlcp_keys.pem should be in sensitive section or have warning
    expect(wrapper.find('.sensitive-files-section').exists()).toBe(true)

    // Action buttons: "前往密钥库" and "完成并关闭"
    expect(wrapper.text()).toContain('前往密钥库')
    expect(wrapper.text()).toContain('完成并关闭')

    // Click "前往密钥库"
    await wrapper.findAll('.wizard-actions button').find(b => b.text().includes('前往密钥库'))!.trigger('click')
    expect(wrapper.emitted('navigate-vault')).toBeTruthy()
  })

  it('renders 4 simple cards (SELF_SIGNED, ROOT_CA, CSR, QUICK_ISSUE) when simpleMode=true, excluding INTERMEDIATE_CA and TLCP', () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities,
        simpleMode: true
      }
    })

    const cards = wrapper.findAll('.profile-card')
    expect(cards).toHaveLength(4)
    const cardTexts = cards.map(c => c.text())
    // 4 simple profiles present:
    expect(cardTexts.some(t => t.includes('单证自签名证书'))).toBe(true)
    expect(cardTexts.some(t => t.includes('自签名根 CA 证书'))).toBe(true)
    expect(cardTexts.some(t => t.includes('证书签名请求 (CSR)'))).toBe(true)
    expect(cardTexts.some(t => t.includes('快速签发服务证书'))).toBe(true)
    // Intermediate CA, CA_SIGN, TLCP excluded:
    expect(cardTexts.some(t => t.includes('二级CA') || t.includes('中间 CA 证书'))).toBe(false)
    expect(cardTexts.some(t => t.includes('CA 签发证书') && !t.includes('快速签发'))).toBe(false)
    expect(cardTexts.some(t => t.includes('国密TLCP') || t.includes('TLCP'))).toBe(false)
  })

  it('provides a direct "创建根 CA" button when QUICK_ISSUE has no CA cert and navigates to ROOT_CA', async () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: [{ id: 'f_other', name: 'data.txt', size: 10, mediaType: 'text/plain', createdAt: '' }],
        capabilities: mockCapabilities,
        simpleMode: true
      }
    })

    // Select QUICK_ISSUE
    const radio = wrapper.findAll('input[name="cert-profile"]').find(i => (i.element as HTMLInputElement).value === 'QUICK_ISSUE')!
    await radio.setValue(true)

    // Step 1 -> Step 2
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('my.service.com')
    // Step 2 -> Step 3
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    // Expect no CA warning banner with action button
    expect(wrapper.text()).toContain('当前项目中暂无可用 CA 证书')
    const createCaBtn = wrapper.find('button.btn-create-root-ca')
    expect(createCaBtn.exists()).toBe(true)

    // Click "创建根 CA" button -> should switch profile to ROOT_CA and jump to step 1
    await createCaBtn.trigger('click')
    expect(wrapper.find('.profile-card.selected').text()).toContain('自签名根 CA 证书')
  })

  it('renders all professional profiles when simpleMode=false (advanced mode)', () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities,
        simpleMode: false
      }
    })

    const cards = wrapper.findAll('.profile-card')
    expect(cards.length).toBeGreaterThanOrEqual(6)
    const cardTexts = cards.map(c => c.text())
    expect(cardTexts.some(t => t.includes('信任根') || t.includes('根 CA'))).toBe(true)
  })

  it('shows clear notice when QUICK_ISSUE is selected in simpleMode without existing CA cert', async () => {
    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-1',
        keys: dummyKeys,
        files: [{ id: 'f_other', name: 'data.txt', size: 10, mediaType: 'text/plain', createdAt: '' }],
        capabilities: mockCapabilities,
        simpleMode: true
      }
    })

    // Select QUICK_ISSUE
    const radio = wrapper.findAll('input[name="cert-profile"]').find(i => (i.element as HTMLInputElement).value === 'QUICK_ISSUE')!
    await radio.setValue(true)

    // Step 1 -> Step 2
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('my.service.com')
    // Step 2 -> Step 3
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')

    // Should see notice that no CA certificate exists in project, with hint to create or use self-signed
    expect(wrapper.text()).toContain('暂无可用 CA 证书')
  })

  it('filters CA select options using realCaNodes when API returns valid CA certificates and excludes expired or non-selectable ones', async () => {
    const certTreeData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:valid-ca',
          name: 'valid_ca.pem',
          category: 'ROOT_CA',
          subjectCN: 'Real Authority CA',
          issuerCN: 'Real Authority CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: [],
          downloadRef: 'file:f-ca-1'
        },
        {
          id: 'cert:expired-ca',
          name: 'expired_ca.pem',
          category: 'ROOT_CA',
          subjectCN: 'Expired Legacy CA',
          issuerCN: 'Expired Legacy CA',
          validityStatus: 'EXPIRED',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: [],
          downloadRef: 'file:f-ca-2'
        },
        {
          id: 'cert:bundle-ca',
          name: 'bundle_only_ca.pem',
          category: 'ROOT_CA',
          subjectCN: 'Bundle Only CA',
          issuerCN: 'Bundle Only CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: [],
          downloadRef: undefined
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async (url: RequestInfo | URL) => {
      if (String(url).includes('/certificates')) {
        return new Response(JSON.stringify(certTreeData), { status: 200 })
      }
      return new Response(JSON.stringify({}), { status: 200 })
    }))

    const wrapper = mount(CertificateWizard, {
      props: {
        projectId: 'proj-real-ca',
        keys: dummyKeys,
        files: dummyFiles,
        capabilities: mockCapabilities,
        simpleMode: true
      }
    })

    // Select QUICK_ISSUE which requires issuer
    const radio = wrapper.findAll('input[name="cert-profile"]').find(i => (i.element as HTMLInputElement).value === 'QUICK_ISSUE')!
    await radio.setValue(true)
    await flushPromises()

    // Step 1 -> Step 2
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await wrapper.get('#subject-cn').setValue('test.service.com')

    // Step 2 -> Step 3
    await wrapper.findAll('.wizard-footer button').find(b => b.text().includes('下一步'))!.trigger('click')
    await flushPromises()

    // Inspect the CA select element options
    const caSelect = wrapper.find('#issuer-cert')
    expect(caSelect.exists()).toBe(true)
    const options = caSelect.findAll('option')

    // Only 'Real Authority CA' with selectableAsIssuer=true and downloadRef should be present
    const optionTexts = options.map(o => o.text())
    expect(optionTexts.some(t => t.includes('Real Authority CA'))).toBe(true)
    expect(optionTexts.some(t => t.includes('Expired Legacy CA'))).toBe(false)
    expect(optionTexts.some(t => t.includes('Bundle Only CA'))).toBe(false)
  })

})
