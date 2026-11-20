import { describe, it, expect, vi, afterEach } from 'vitest'
import { getKeyGenSpec, generateRandomHex } from '../src/key-generator'
import { parameter } from './fixtures'

describe('key-generator helper', () => {
  afterEach(() => {
    vi.restoreAllMocks()
    vi.unstubAllGlobals()
  })

  it('maps SM4 normal to 128 bits and SM4 XTS to 256 bits', () => {
    const keyParam = parameter({ name: 'key', flag: '-key', type: 'HEX', secret: true, allowKeyReference: true })
    expect(getKeyGenSpec('sm4_cbc', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('sm4_ecb', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('sm4_gcm', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('sm4_xts', keyParam)?.defaultBits).toBe(256)
  })

  it('maps ZUC-128 and ZUC-256 variants correctly', () => {
    const keyParam = parameter({ name: 'key', flag: '-key', type: 'HEX', secret: true, allowKeyReference: true })
    expect(getKeyGenSpec('zuc', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('zuc_128_eea3', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('zuc_128_eia3', keyParam)?.defaultBits).toBe(128)
    expect(getKeyGenSpec('zuc256', keyParam)?.defaultBits).toBe(256)
  })

  it('maps HMAC key to default 256 bits', () => {
    const keyParam = parameter({ name: 'key', flag: '-key', type: 'HEX', secret: true, allowKeyReference: true })
    expect(getKeyGenSpec('sm3_hmac', keyParam)?.defaultBits).toBe(256)
  })

  it('offers 128, 192, and 256 bit options for AES', () => {
    const keyParam = parameter({ name: 'key', flag: '-key', type: 'HEX', secret: true, allowKeyReference: true })
    const spec = getKeyGenSpec('aes_128_cbc', keyParam)
    expect(spec?.defaultBits).toBe(128)
    expect(spec?.options?.map(o => o.bits)).toEqual([128, 192, 256])
  })

  it('refuses generation for INPUT_FILE, non-HEX, SM2 private keys, rawEC scalars, or unknown secrets', () => {
    const fileParam = parameter({ name: 'key', flag: '-key', type: 'INPUT_FILE' })
    const passParam = parameter({ name: 'pass', flag: '-pass', type: 'SECRET', secret: true })
    const ivParam = parameter({ name: 'iv', flag: '-iv', type: 'HEX', secret: false })
    const ecParam = parameter({ name: 'k', flag: '-k', type: 'HEX', secret: true })
    expect(getKeyGenSpec('sm4_cbc', fileParam)).toBeNull()
    expect(getKeyGenSpec('sm4_cbc', passParam)).toBeNull()
    expect(getKeyGenSpec('sm4_cbc', ivParam)).toBeNull()
    expect(getKeyGenSpec('sm2sign', ecParam)).toBeNull()
    expect(getKeyGenSpec('unknown_tool', ecParam)).toBeNull()
  })

  it('generates valid hex strings of exact length', () => {
    const hex16 = generateRandomHex(16)
    expect(hex16).toMatch(/^[0-9a-f]{32}$/)
    const hex32 = generateRandomHex(32)
    expect(hex32).toMatch(/^[0-9a-f]{64}$/)
    const hex24 = generateRandomHex(24)
    expect(hex24).toMatch(/^[0-9a-f]{48}$/)
  })

  it('produces different values across successive calls (no hardcoded return)', () => {
    const a = generateRandomHex(16)
    const b = generateRandomHex(16)
    expect(a).not.toBe(b)
  })

  it('throws explicit error when browser crypto.getRandomValues is unavailable and does not fallback to Math.random', () => {
    const mathSpy = vi.spyOn(Math, 'random')
    vi.stubGlobal('crypto', undefined)
    expect(() => generateRandomHex(16)).toThrow('浏览器随机源不可用')
    expect(mathSpy).not.toHaveBeenCalled()
  })
})
