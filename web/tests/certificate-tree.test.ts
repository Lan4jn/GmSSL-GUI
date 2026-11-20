import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount, flushPromises } from '@vue/test-utils'
import CertificateTree from '../src/components/CertificateTree.vue'
import type { CertificateTreeResponse } from '../src/types'

const dummyTreeData: CertificateTreeResponse = {
  nodes: [
    {
      id: 'cert-root-1',
      name: 'root_ca.pem',
      category: 'ROOT_CA',
      subjectCN: 'GmSSL Root CA',
      issuerCN: 'GmSSL Root CA',
      serialNumber: '00A1B2C3',
      validBefore: '2026-01-01T00:00:00Z',
      validAfter: '2036-01-01T00:00:00Z',
      validityStatus: 'VALID',
      revocationStatus: 'UNCHECKED',
      isCa: true,
      selectableAsIssuer: true,
      parentRefs: []
    },
    {
      id: 'cert-sub-1',
      name: 'sub_ca.pem',
      category: 'INTERMEDIATE_CA',
      subjectCN: 'GmSSL Sub CA',
      issuerCN: 'GmSSL Root CA',
      serialNumber: '00A1B2C4',
      validBefore: '2026-01-01T00:00:00Z',
      validAfter: '2031-01-01T00:00:00Z',
      validityStatus: 'VALID',
      revocationStatus: 'UNCHECKED',
      isCa: true,
      selectableAsIssuer: true,
      parentRefs: ['cert-root-1']
    },
    {
      id: 'cert-leaf-1',
      name: 'server_cert.pem',
      category: 'ISSUED_CERT',
      subjectCN: 'api.service.test',
      issuerCN: 'GmSSL Sub CA',
      serialNumber: '00A1B2C5',
      validBefore: '2026-01-01T00:00:00Z',
      validAfter: '2027-01-01T00:00:00Z',
      validityStatus: 'VALID',
      revocationStatus: 'UNCHECKED',
      isCa: false,
      selectableAsIssuer: false,
      parentRefs: ['cert-sub-1']
    },
    {
      id: 'cert-self-1',
      name: 'standalone.pem',
      category: 'SELF_SIGNED_END_ENTITY',
      subjectCN: 'standalone.local',
      issuerCN: 'standalone.local',
      serialNumber: '00A1B2C6',
      validBefore: '2026-01-01T00:00:00Z',
      validAfter: '2027-01-01T00:00:00Z',
      validityStatus: 'VALID',
      revocationStatus: 'UNCHECKED',
      isCa: false,
      selectableAsIssuer: false,
      parentRefs: []
    },
    {
      id: 'cert-orphan-1',
      name: 'external_leaf.pem',
      category: 'ORPHAN',
      subjectCN: 'external.example.com',
      issuerCN: 'Unknown Foreign CA',
      validityStatus: 'VALID',
      revocationStatus: 'UNCHECKED',
      isCa: false,
      selectableAsIssuer: false,
      parentRefs: []
    }
  ],
  csrs: [
    {
      id: 'csr-1',
      name: 'service.csr',
      subjectCN: 'gateway.internal',
      createdAt: '2026-01-01T00:00:00Z'
    }
  ],
  bundles: [
    {
      id: 'b-1',
      name: 'fullchain.pem',
      containsCertIds: ['cert-leaf-1', 'cert-sub-1', 'cert-root-1']
    }
  ]
}

describe('CertificateTree.vue component', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('renders root CA node and expands to child intermediate CA and leaf certificate', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: {
        projectId: 'proj-tree-1'
      }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('GmSSL Root CA')
    expect(wrapper.text()).toContain('根 CA')

    // Children are rendered under the tree
    expect(wrapper.text()).toContain('GmSSL Sub CA')
    expect(wrapper.text()).toContain('api.service.test')
  })

  it('separately groups self-signed end-entity, orphan certificates, and CSRs', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: {
        projectId: 'proj-tree-1'
      }
    })
    await flushPromises()

    // Self-signed end-entity section
    expect(wrapper.text()).toContain('自签名终端服务证书')
    expect(wrapper.text()).toContain('standalone.local')

    // Orphan / missing CA section
    expect(wrapper.text()).toContain('外部或缺失上级 CA')
    expect(wrapper.text()).toContain('external.example.com')

    // CSR requests section
    expect(wrapper.text()).toContain('证书申请文件 (CSR)')
    expect(wrapper.text()).toContain('gateway.internal')
  })

  it('filters certificates by search query (CN, name, serial)', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: {
        projectId: 'proj-tree-1'
      }
    })
    await flushPromises()

    const searchInput = wrapper.get('input.tree-search-input')
    await searchInput.setValue('standalone')

    expect(wrapper.find('.tree-content').text()).toContain('standalone.local')
    expect(wrapper.find('.tree-content').text()).not.toContain('GmSSL Sub CA')
  })

  it('protects against cyclic parentRefs without infinite recursion', async () => {
    const cyclicData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'c-1',
          name: 'c1.pem',
          category: 'INTERMEDIATE_CA',
          subjectCN: 'Cycle Node 1',
          issuerCN: 'Cycle Node 2',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: ['c-2']
        },
        {
          id: 'c-2',
          name: 'c2.pem',
          category: 'INTERMEDIATE_CA',
          subjectCN: 'Cycle Node 2',
          issuerCN: 'Cycle Node 1',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: ['c-1']
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(cyclicData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: {
        projectId: 'proj-tree-cycle'
      }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('Cycle Node 1')
    expect(wrapper.text()).toContain('Cycle Node 2')
  })

  it('triggers download for individual certificate or bundle file', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: {
        projectId: 'proj-tree-1'
      }
    })
    await flushPromises()

    const downloadBtn = wrapper.findAll('button.download-btn').find(b => b.attributes('aria-label')?.includes('root_ca.pem'))
    expect(downloadBtn).toBeDefined()
  })

  it('correctly distinguishes same-name CAs with different serial numbers and file names', async () => {
    const sameNameData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'ca-v1',
          name: 'root_ca_2020.pem',
          category: 'ROOT_CA',
          subjectCN: 'Corporate Root CA',
          issuerCN: 'Corporate Root CA',
          serialNumber: 'SERIAL-2020-001',
          validityStatus: 'EXPIRED',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: []
        },
        {
          id: 'ca-v2',
          name: 'root_ca_2025.pem',
          category: 'ROOT_CA',
          subjectCN: 'Corporate Root CA',
          issuerCN: 'Corporate Root CA',
          serialNumber: 'SERIAL-2025-002',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(sameNameData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-same-name' }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('root_ca_2020.pem')
    expect(wrapper.text()).toContain('root_ca_2025.pem')
    expect(wrapper.text()).toContain('SERIAL-2020-001')
    expect(wrapper.text()).toContain('SERIAL-2025-002')
    expect(wrapper.text()).toContain('已过期不可签发')
    expect(wrapper.text()).toContain('可签发')
  })

  it('renders multi-parent cross-signed certificates under each parent node without duplication errors', async () => {
    const crossSignData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'root-a',
          name: 'root_a.pem',
          category: 'ROOT_CA',
          subjectCN: 'Root CA A',
          issuerCN: 'Root CA A',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        },
        {
          id: 'root-b',
          name: 'root_b.pem',
          category: 'ROOT_CA',
          subjectCN: 'Root CA B',
          issuerCN: 'Root CA B',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        },
        {
          id: 'cross-sub',
          name: 'cross_sub_ca.pem',
          category: 'INTERMEDIATE_CA',
          subjectCN: 'Cross Signed Sub CA',
          issuerCN: 'Cross Signed',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: ['root-a', 'root-b']
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(crossSignData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-cross-sign' }
    })
    await flushPromises()

    // Root CA A branch and Root CA B branch should both contain Cross Signed Sub CA
    const treeBranches = wrapper.findAll('.tree-branch')
    expect(treeBranches).toHaveLength(2)
    expect(treeBranches[0].text()).toContain('Cross Signed Sub CA')
    expect(treeBranches[1].text()).toContain('Cross Signed Sub CA')
  })

  it('alerts when attempting to download a bundle-only certificate without downloadRef', async () => {
    const bundleOnlyData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:bundle-only-hash',
          name: 'bundled_leaf.pem',
          category: 'SELF_SIGNED_END_ENTITY',
          subjectCN: 'bundle.leaf.local',
          issuerCN: 'bundle.leaf.local',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: [],
          downloadRef: undefined,
          sourceFileRef: undefined
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(bundleOnlyData), { status: 200 })
    ))
    const alertSpy = vi.fn()
    vi.stubGlobal('alert', alertSpy)

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-bundle-only' }
    })
    await flushPromises()

    const dlBtn = wrapper.find('button.download-btn')
    await dlBtn.trigger('click')
    expect(alertSpy).toHaveBeenCalledWith(expect.stringContaining('仅包含于证书链合辑 (Bundle) 中'))
  })

  it('renders unsupported and engine pending nodes in a distinct section with error message', async () => {
    const errorData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:corrupt',
          name: 'corrupted_cert.pem',
          category: 'UNSUPPORTED',
          subjectCN: 'corrupted_cert.pem',
          issuerCN: '',
          validityStatus: 'UNKNOWN',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: [],
          error: 'DER ASN.1 解码失败: 尾部多余字节'
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(errorData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-err' }
    })
    await flushPromises()

    expect(wrapper.text()).toContain('待解析或格式不支持材料')
    expect(wrapper.text()).toContain('corrupted_cert.pem')
    expect(wrapper.text()).toContain('DER ASN.1 解码失败: 尾部多余字节')
  })

  it('filters certificates by categoryFilter and validityFilter', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-tree-filter' }
    })
    await flushPromises()

    // Filter by ROOT_CA only
    const catSelect = wrapper.find('select.type-select')
    await catSelect.setValue('ROOT_CA')

    expect(wrapper.find('.tree-content').text()).toContain('GmSSL Root CA')
    expect(wrapper.find('.tree-content').text()).not.toContain('standalone.local')

    // Filter by validityStatus EXPIRED
    const valSelect = wrapper.find('select.validity-select')
    await valSelect.setValue('EXPIRED')

    // Since dummyTreeData has no expired certs, no root CA should match
    expect(wrapper.find('.tree-content').text()).not.toContain('GmSSL Root CA')

    // Switch back to VALID
    await valSelect.setValue('VALID')
    expect(wrapper.find('.tree-content').text()).toContain('GmSSL Root CA')
  })

  it('differentiates same-name CAs by logical ID in ca-select and strictly filters to the selected CA descendants', async () => {
    const multiCaData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'ca-branch-1',
          name: 'ca_2024.pem',
          category: 'ROOT_CA',
          subjectCN: 'Cluster Root CA',
          issuerCN: 'Cluster Root CA',
          serialNumber: 'SN-001',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        },
        {
          id: 'leaf-branch-1',
          name: 'server_1.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'service1.cluster.local',
          issuerCN: 'Cluster Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: ['ca-branch-1']
        },
        {
          id: 'ca-branch-2',
          name: 'ca_2025.pem',
          category: 'ROOT_CA',
          subjectCN: 'Cluster Root CA',
          issuerCN: 'Cluster Root CA',
          serialNumber: 'SN-002',
          validityStatus: 'EXPIRED',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: false,
          parentRefs: []
        },
        {
          id: 'leaf-branch-2',
          name: 'server_2.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'service2.cluster.local',
          issuerCN: 'Cluster Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: ['ca-branch-2']
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(multiCaData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-same-cn' }
    })
    await flushPromises()

    const caSelect = wrapper.find('select.ca-select')
    expect(caSelect.exists()).toBe(true)
    const options = caSelect.findAll('option')

    // Both same-name CAs must be in the options by their logical id
    expect(options.some(o => o.attributes('value') === 'ca-branch-1')).toBe(true)
    expect(options.some(o => o.attributes('value') === 'ca-branch-2')).toBe(true)
    // Expired CA is selectable as a filter option
    expect(options.find(o => o.attributes('value') === 'ca-branch-2')!.text()).toContain('已过期')

    // Select branch 1: only ca-branch-1 and its leaf should appear
    await caSelect.setValue('ca-branch-1')
    expect(wrapper.find('.tree-content').text()).toContain('ca_2024.pem')
    expect(wrapper.find('.tree-content').text()).toContain('service1.cluster.local')
    expect(wrapper.find('.tree-content').text()).not.toContain('ca_2025.pem')
    expect(wrapper.find('.tree-content').text()).not.toContain('service2.cluster.local')

    // Select branch 2: only ca-branch-2 and its leaf should appear
    await caSelect.setValue('ca-branch-2')
    expect(wrapper.find('.tree-content').text()).toContain('ca_2025.pem')
    expect(wrapper.find('.tree-content').text()).toContain('service2.cluster.local')
    expect(wrapper.find('.tree-content').text()).not.toContain('ca_2024.pem')
    expect(wrapper.find('.tree-content').text()).not.toContain('service1.cluster.local')
  })

  it('filters recursively for intermediate CA and supports multi-parent nodes', async () => {
    const tieredData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'tier-root',
          name: 'root.pem',
          category: 'ROOT_CA',
          subjectCN: 'Tiered Root CA',
          issuerCN: 'Tiered Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        },
        {
          id: 'tier-mid',
          name: 'intermediate.pem',
          category: 'INTERMEDIATE_CA',
          subjectCN: 'Tiered Intermediate CA',
          issuerCN: 'Tiered Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: ['tier-root']
        },
        {
          id: 'tier-leaf',
          name: 'app.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'app.tiered.com',
          issuerCN: 'Tiered Intermediate CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: ['tier-mid']
        }
      ],
      csrs: [],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(tieredData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-tiered' }
    })
    await flushPromises()

    const caSelect = wrapper.find('select.ca-select')

    // Selecting intermediate CA: should show intermediate CA and leaf
    await caSelect.setValue('tier-mid')
    expect(wrapper.text()).toContain('Tiered Intermediate CA')
    expect(wrapper.text()).toContain('app.tiered.com')

    // CSRs should not show when specific CA is filtered
    expect(wrapper.findAll('.tree-section').some(s => s.text().includes('证书申请文件 (CSR)'))).toBe(false)
  })

  it('resets selectedCaId when projectId changes', async () => {
    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(dummyTreeData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-p1' }
    })
    await flushPromises()

    const caSelect = wrapper.find('select.ca-select')
    await caSelect.setValue('cert-root-1')
    expect((caSelect.element as HTMLSelectElement).value).toBe('cert-root-1')

    // Switch projectId prop
    await wrapper.setProps({ projectId: 'proj-p2' })
    await flushPromises()

    expect((wrapper.find('select.ca-select').element as HTMLSelectElement).value).toBe('ALL')
  })

  it('renders matched CSR badge and download button on certificate nodes', async () => {
    const certWithCsrData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:leaf-with-csr',
          name: 'server_cert.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'api.demo.com',
          issuerCN: 'Demo CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: [],
          downloadRef: 'file:f-cert',
          matchedCsrRefs: ['file:f-csr-1'],
          csrMatchEvidence: 'KEY_AND_SUBJECT_MATCH'
        }
      ],
      csrs: [
        {
          id: 'file:f-csr-1',
          name: 'server_req.csr',
          subjectCN: 'api.demo.com',
          createdAt: '2026-01-01T00:00:00Z',
          matchedCertIds: ['cert:leaf-with-csr'],
          matchKind: 'KEY_AND_SUBJECT_MATCH',
          ambiguous: false
        }
      ],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(certWithCsrData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-csr-link' }
    })
    await flushPromises()

    // Certificate node should display matched CSR badge and download CSR button
    expect(wrapper.text()).toContain('关联 CSR:')
    expect(wrapper.text()).toContain('server_req.csr')
    expect(wrapper.text()).toContain('公钥与主体一致')

    const downloadCsrBtn = wrapper.find('button[aria-label="下载关联 CSR server_req.csr"]')
    expect(downloadCsrBtn.exists()).toBe(true)
  })

  it('renders reverse certificate matching info in CSR section and allows locating certificate', async () => {
    const csrReverseData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:target-cert',
          name: 'target_cert.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'target.cluster.local',
          issuerCN: 'Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: ['cert:root-ca'],
          downloadRef: 'file:f-target',
          matchedCsrRefs: ['file:f-csr-target'],
          csrMatchEvidence: 'KEY_AND_SUBJECT_MATCH'
        },
        {
          id: 'cert:root-ca',
          name: 'root.pem',
          category: 'ROOT_CA',
          subjectCN: 'Root CA',
          issuerCN: 'Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: true,
          selectableAsIssuer: true,
          parentRefs: []
        }
      ],
      csrs: [
        {
          id: 'file:f-csr-target',
          name: 'target.csr',
          subjectCN: 'target.cluster.local',
          createdAt: '2026-01-01T00:00:00Z',
          matchedCertIds: ['cert:target-cert'],
          matchKind: 'KEY_AND_SUBJECT_MATCH',
          ambiguous: false
        },
        {
          id: 'file:f-csr-unmatched',
          name: 'unmatched.csr',
          subjectCN: 'standalone.csr.com',
          createdAt: '2026-01-01T00:00:00Z',
          matchedCertIds: [],
          matchKind: 'UNMATCHED',
          ambiguous: false
        },
        {
          id: 'file:f-csr-bad',
          name: 'corrupt.csr',
          subjectCN: '',
          createdAt: '2026-01-01T00:00:00Z',
          matchKind: 'INVALID_CSR',
          error: 'CSR 请求签名校验失败'
        }
      ],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(csrReverseData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-csr-reverse' }
    })
    await flushPromises()

    // Check CSR section labels
    expect(wrapper.text()).toContain('target.cluster.local')
    expect(wrapper.text()).toContain('对应证书:')
    expect(wrapper.text()).toContain('target_cert.pem')
    expect(wrapper.text()).toContain('未找到匹配证书')
    expect(wrapper.text()).toContain('CSR格式或签名无效')
    expect(wrapper.text()).toContain('CSR 请求签名校验失败')

    // Click locate certificate button
    const locateBtn = wrapper.find('button[aria-label="在树中定位证书 target_cert.pem"]')
    expect(locateBtn.exists()).toBe(true)
    await locateBtn.trigger('click')
    await flushPromises()

    // Target node should be expanded in the tree
    expect(wrapper.find('#cert-node-cert\\:target-cert').exists()).toBe(true)
  })

  it('differentiates ambiguous labels: 多份材料匹配（非唯一来源） for 1 cert vs 多张证书匹配（非唯一来源） for multiple certs', async () => {
    const ambiguousData: CertificateTreeResponse = {
      nodes: [
        {
          id: 'cert:cert-a',
          name: 'cert_a.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'app.example.com',
          issuerCN: 'Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: []
        },
        {
          id: 'cert:cert-b',
          name: 'cert_b.pem',
          category: 'ISSUED_CERT',
          subjectCN: 'app.example.com',
          issuerCN: 'Root CA',
          validityStatus: 'VALID',
          revocationStatus: 'UNCHECKED',
          isCa: false,
          selectableAsIssuer: false,
          parentRefs: []
        }
      ],
      csrs: [
        {
          id: 'file:csr-1-cert',
          name: 'csr_one_cert.csr',
          subjectCN: 'app.example.com',
          createdAt: '2026-01-01T00:00:00Z',
          matchedCertIds: ['cert:cert-a'],
          matchKind: 'KEY_AND_SUBJECT_MATCH',
          ambiguous: true
        },
        {
          id: 'file:csr-multi-cert',
          name: 'csr_two_certs.csr',
          subjectCN: 'app.example.com',
          createdAt: '2026-01-01T00:00:00Z',
          matchedCertIds: ['cert:cert-a', 'cert:cert-b'],
          matchKind: 'KEY_AND_SUBJECT_MATCH',
          ambiguous: true
        }
      ],
      bundles: []
    }

    vi.stubGlobal('fetch', vi.fn(async () =>
      new Response(JSON.stringify(ambiguousData), { status: 200 })
    ))

    const wrapper = mount(CertificateTree, {
      props: { projectId: 'proj-csr-ambiguous' }
    })
    await flushPromises()

    // 1 cert matching with ambiguous: true -> "多份材料匹配（非唯一来源）"
    expect(wrapper.text()).toContain('多份材料匹配（非唯一来源）')

    // Multiple certs matching -> "多张证书匹配（非唯一来源）"
    expect(wrapper.text()).toContain('多张证书匹配（非唯一来源）')
  })
})
