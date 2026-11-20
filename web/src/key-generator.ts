import type { Parameter } from './types'

export interface KeyGenerationOption {
  bits: number
  bytes: number
  label: string
}

export interface KeyGenSpec {
  defaultBits: number
  options?: KeyGenerationOption[]
}

/**
 * 判断特定工具和参数是否属于支持随机生成的原始对称密钥 HEX 字段。
 * 不得对 INPUT_FILE、非 HEX、SM2 私钥、rawEC 标量或未知 secret 猜测生成。
 */
export function getKeyGenSpec(toolId?: string, parameter?: Parameter): KeyGenSpec | null {
  if (!toolId || !parameter) return null
  if (parameter.type !== 'HEX') return null

  // 必须是明确的对称 key 参数
  const isKey = parameter.name === 'key' || parameter.flag === '-key' || !!parameter.allowKeyReference
  if (!isKey) return null

  const id = toolId.toLowerCase()
  if (id.startsWith('sm4') || id.includes('sm4')) {
    if (id.includes('xts')) {
      return { defaultBits: 256 }
    }
    return { defaultBits: 128 }
  }
  if (id.startsWith('zuc') || id.includes('zuc')) {
    if (id.includes('256')) {
      return { defaultBits: 256 }
    }
    return { defaultBits: 128 }
  }
  if (id.includes('hmac')) {
    return { defaultBits: 256 }
  }
  if (id.includes('aes')) {
    return {
      defaultBits: 128,
      options: [
        { bits: 128, bytes: 16, label: '128 位 (16 字节)' },
        { bits: 192, bytes: 24, label: '192 位 (24 字节)' },
        { bits: 256, bytes: 32, label: '256 位 (32 字节)' },
      ],
    }
  }
  return null
}

/**
 * 使用 CSPRNG (crypto.getRandomValues) 安全生成指定字节数的十六进制字符串。
 * 在普通 HTTP、IPv6 等任意上下文均可安全运行（不使用 crypto.subtle）。
 * 若浏览器或环境不可用，抛出显式错误，不回退 Math.random。
 */
export function generateRandomHex(bytesCount: number): string {
  const cryptoObj = typeof globalThis !== 'undefined' ? globalThis.crypto : undefined
  if (!cryptoObj || typeof cryptoObj.getRandomValues !== 'function') {
    throw new Error('浏览器随机源不可用')
  }
  const bytes = new Uint8Array(bytesCount)
  cryptoObj.getRandomValues(bytes)
  let hex = ''
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, '0')
  }
  return hex
}
