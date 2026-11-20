import { describe, it, expect, vi, afterEach } from 'vitest'
import { mount } from '@vue/test-utils'
import SimpleWorkbench from '../src/components/SimpleWorkbench.vue'
import type { Key, ManagedFile } from '../src/types'

const dummyKeys: Key[] = [
  {
    id: 'k1',
    projectId: 'p1',
    name: 'ca.key',
    algorithm: 'SM2',
    keyKind: 'PRIVATE_KEY',
    encoding: 'PEM',
    validationStatus: 'VALIDATED',
    createdAt: '2026-01-01T00:00:00Z',
    updatedAt: '2026-01-01T00:00:00Z',
    stateful: false
  }
]

const dummyFiles: ManagedFile[] = [
  {
    id: 'f1',
    name: 'root_ca.pem',
    size: 1024,
    mediaType: 'application/x-x509-ca-cert',
    createdAt: '2026-01-01T00:00:00Z'
  }
]

describe('SimpleWorkbench component', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('renders prominent certificate wizard primary card and core certificate cards on first screen', () => {
    const wrapper = mount(SimpleWorkbench, {
      props: {
        projectId: 'p1',
        keys: dummyKeys,
        files: dummyFiles,
        disabled: false
      }
    })

    expect(wrapper.text()).toContain('快捷安全密码任务')
    expect(wrapper.text()).toContain('制作国密 / X.509 证书')

    // Certificate-focused cards
    expect(wrapper.text()).toContain('制作证书')
    expect(wrapper.text()).toContain('我的材料库')

    // Non-certificate generic tools are excluded from simple mode cards
    expect(wrapper.find('.cards-grid').text()).not.toContain('生成密钥')
    expect(wrapper.find('.cards-grid').text()).not.toContain('文件加解密')
    expect(wrapper.find('.cards-grid').text()).not.toContain('数字签名')
    expect(wrapper.find('.cards-grid').text()).not.toContain('哈希摘要')

    // Primary prominent start wizard button
    const certStartBtn = wrapper.findAll('button').find(b => b.text().includes('开始制作证书'))
    expect(certStartBtn).toBeDefined()
  })

  it('opens certificate wizard directly in simple mode on clicking start wizard button', async () => {
    const wrapper = mount(SimpleWorkbench, {
      props: {
        projectId: 'p1',
        keys: dummyKeys,
        files: dummyFiles,
        disabled: false
      }
    })

    const certStartBtn = wrapper.findAll('button').find(b => b.text().includes('开始制作证书'))!
    await certStartBtn.trigger('click')

    // Wizard should now be open
    expect(wrapper.find('.simple-wizard-container').exists()).toBe(true)
    expect(wrapper.text()).toContain('证书制作向导')

    // Verify CertificateWizard opened in simpleMode displays exactly 4 simple cards
    const profileCards = wrapper.findAll('.profile-card')
    expect(profileCards).toHaveLength(4)
    const cardTexts = profileCards.map(c => c.text())
    expect(cardTexts.some(t => t.includes('单证自签名证书'))).toBe(true)
    expect(cardTexts.some(t => t.includes('自签名根 CA 证书'))).toBe(true)
    expect(cardTexts.some(t => t.includes('证书签名请求 (CSR)'))).toBe(true)
    expect(cardTexts.some(t => t.includes('快速签发服务证书'))).toBe(true)
  })

  it('opens certificate wizard on clicking card button and emits navigate-vault', async () => {
    const wrapper = mount(SimpleWorkbench, {
      props: {
        projectId: 'p1',
        keys: dummyKeys,
        files: dummyFiles,
        disabled: false
      }
    })

    // Click card 1 button -> opens wizard
    const certCardBtn = wrapper.findAll('button').find(b => b.text().includes('打开证书向导'))!
    await certCardBtn.trigger('click')
    expect(wrapper.find('.simple-wizard-container').exists()).toBe(true)

    // Close wizard
    await wrapper.find('.scene-header button').trigger('click')
    expect(wrapper.find('.simple-wizard-container').exists()).toBe(false)

    // Click card 2 button -> emits navigate-vault
    const vaultBtn = wrapper.findAll('button').find(b => b.text().includes('前往材料库'))!
    await vaultBtn.trigger('click')
    expect(wrapper.emitted('navigate-vault')).toBeTruthy()
  })
})
