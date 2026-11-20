import { spawn } from 'node:child_process'
import { mkdir, readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const artifacts = join(root, 'tests/artifacts')
const base = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173'
const browserPath = process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const env = { ...process.env }
if (process.env.E2E_ENV_FILE) {
  const text = await readFile(resolve(process.env.E2E_ENV_FILE), 'utf8')
  for (const line of text.split('\n')) {
    const match = line.match(/^(?:export\s+)?([A-Z_]+)=(.*)$/)
    if (match && ['GMSSL_BOOTSTRAP_USERNAME','GMSSL_BOOTSTRAP_PASSWORD'].includes(match[1])) env[match[1]] = match[2].replace(/^['"]|['"]$/g,'')
  }
}
const username = env.E2E_USERNAME ?? env.GMSSL_BOOTSTRAP_USERNAME
const password = env.E2E_PASSWORD ?? env.GMSSL_BOOTSTRAP_PASSWORD
await mkdir(artifacts, { recursive: true })
const profile = await mkdtemp(join(tmpdir(), 'gmssl-web-cdp-sm4-roundtrip-'))
let chrome, socket, nextId = 0
const pending = new Map(), errors = []
const sleep = ms => new Promise(r => setTimeout(r, ms))
const send = (method, params = {}) => new Promise((resolve, reject) => {
  const id = ++nextId; const timer = setTimeout(() => { pending.delete(id); reject(new Error(`CDP timeout: ${method}`)) }, 15000)
  pending.set(id, { resolve: v => { clearTimeout(timer); resolve(v) }, reject: e => { clearTimeout(timer); reject(e) } })
  socket.send(JSON.stringify({ id, method, params }))
})
async function evaluate(expression) {
  const result = await send('Runtime.evaluate', { expression, returnByValue: true, awaitPromise: true })
  if (result.exceptionDetails) throw new Error('Browser expression failed: ' + JSON.stringify(result.exceptionDetails))
  return result.result.value
}
async function until(expression, label) {
  for (let i = 0; i < 200; i++) {
    if (await evaluate(expression)) return
    await sleep(150)
  }
  throw new Error(`UI timeout: ${label}`)
}
async function capture(name, width = 1440, height = 1000) {
  await send('Emulation.setDeviceMetricsOverride', { width, height, deviceScaleFactor: 1, mobile: width < 720 })
  await sleep(250)
  const shot = await send('Page.captureScreenshot', { format: 'png', captureBeyondViewport: false })
  await writeFile(join(artifacts, `${name}.png`), Buffer.from(shot.data, 'base64'))
}
const setInput = (selector, value) => `(()=>{const e=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}))})()`
const setTextarea = (selector, value) => `(()=>{const e=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}))})()`
async function clickText(selector, text) {
  return evaluate(`(()=>{const e=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.trim()===${JSON.stringify(text)});if(!e)throw Error('missing target: '+${JSON.stringify(text)});e.click()})()`)
}

try {
  if (!(await fetch(base)).ok) throw new Error('Frontend is not ready on ' + base)
  chrome = spawn(browserPath, ['--headless', '--disable-gpu', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${profile}`, '--remote-debugging-port=0', 'about:blank'], { stdio: 'ignore' })
  let port
  for (let i = 0; i < 60; i++) {
    try {
      port = (await readFile(join(profile, 'DevToolsActivePort'), 'utf8')).split('\n')[0]
      break
    } catch {
      await sleep(150)
    }
  }
  if (!port) throw new Error('Chrome CDP failed to start')
  const targets = await (await fetch(`http://127.0.0.1:${port}/json/list`)).json()
  const target = targets.find(t => t.type === 'page')
  socket = new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve, reject) => { socket.onopen = resolve; socket.onerror = reject })
  socket.onmessage = event => {
    const msg = JSON.parse(event.data)
    if (msg.id) {
      const p = pending.get(msg.id)
      if (!p) return
      pending.delete(msg.id)
      msg.error ? p.reject(new Error('CDP operation failed')) : p.resolve(msg.result)
    } else if (msg.method === 'Runtime.exceptionThrown') {
      errors.push('Uncaught browser runtime exception')
    }
  }

  await send('Runtime.enable')
  await send('Page.enable')
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: base })
  await until("!!document.querySelector('.login-card')", 'login screen')

  if (!username || !password) throw new Error('No credentials for SM4 browser test')

  await evaluate(setInput('#username', username))
  await evaluate(setInput('#password', password))
  await evaluate("document.querySelector('.login-card form').requestSubmit()")
  await until("!!document.querySelector('.app-shell')", 'authenticated workspace')
  await until("!document.querySelector('.loading-line')", 'project loaded')

  // 1. 进入算法工具 -> 检索 sm4_ecb
  await clickText('nav button', '算法工具')
  await until("!!document.querySelector('.search-bar input')", 'catalog loaded')
  await evaluate(setInput('.search-bar input', 'sm4_ecb'))
  await until("[...document.querySelectorAll('.tool-card')].some(e=>e.querySelector('code')?.textContent==='sm4_ecb')", 'sm4_ecb card')
  await evaluate("[...document.querySelectorAll('.tool-card')].find(e=>e.querySelector('code')?.textContent==='sm4_ecb').click()")
  await until("!!document.querySelector('.tool-form')", 'sm4_ecb form')

  // 2. 验证操作模式 Radio 默认选中 加密 (-encrypt)
  const encChecked = await evaluate("document.querySelector('input[type=radio][value=encrypt]')?.checked")
  const decChecked = await evaluate("document.querySelector('input[type=radio][value=decrypt]')?.checked")
  if (!encChecked || decChecked) throw new Error(`Default operation mode invalid: enc=${encChecked}, dec=${decChecked}`)

  // 3. 验证空提交产生「此项为必填」错误
  await evaluate("document.querySelector('.tool-form').requestSubmit()")
  await until("document.querySelector('.field-error')?.textContent.includes('此项为必填')", 'required error on empty submit')

  // 4. 点击「随机生成密钥」，验证必填错误即时消失并填入 32-hex 密钥（长度确证，日志不输出明文密钥）
  await evaluate("(()=>{const b=[...document.querySelectorAll('.tool-form button')].find(b=>b.textContent.includes('随机生成密钥'));b.click();})()")
  await until("!document.querySelector('.field:has(input[aria-label=key]) .field-error')", 'required error cleared on keygen')
  await until("document.querySelector('.key-gen-notice')?.textContent.includes('已生成 128 位随机密钥')", 'notice shown')
  await until("[...document.querySelectorAll('.tool-form button')].some(b=>b.textContent.includes('覆盖生成随机密钥'))", 'overwrite button')

  const keyLen = await evaluate("document.querySelector('.secret-input-wrap input')?.value?.length")
  if (keyLen !== 32) throw new Error(`Invalid generated key length: expected 32, got ${keyLen}`)

  // 5. 校验非 16 字节整倍数输入拦截：输入 5 字节明文 'hello'
  await evaluate(setTextarea('.tool-form textarea', 'hello'))
  await evaluate("document.querySelector('.tool-form').requestSubmit()")
  await until("document.querySelector('.field-error')?.textContent.includes('SM4 ECB 模式无填充，输入长度须为 16 字节整数倍')", 'non-16-byte input intercepted')

  // 6. 输入合法 32 字节（16 字节整数倍）明文
  const validPlaintext32B = '0123456789abcdef0123456789abcdef'
  await evaluate(setTextarea('.tool-form textarea', validPlaintext32B))

  // 模糊处理密钥后截图作为表单证据（安全脱敏）
  await evaluate("(()=>{const input=document.querySelector('.secret-input-wrap input');if(input){input.style.filter='blur(6px)';}})()")
  await capture('sm4-ecb-encrypt-form', 1440, 1000)
  await evaluate("(()=>{const input=document.querySelector('.secret-input-wrap input');if(input){input.style.filter='';}})()")

  // 7. 提交加密任务并等待完成
  await evaluate("document.querySelector('.tool-form').requestSubmit()")
  await until("!!document.querySelector('.job-detail .badge.good') || !!document.querySelector('.job-detail .badge.bad')", 'encryption job settled')

  const encStatus = await evaluate("document.querySelector('.job-detail .badge')?.textContent")
  if (!encStatus?.includes('成功') && !encStatus?.includes('SUCCEEDED')) {
    const jobError = await evaluate("document.querySelector('.banner.error')?.textContent")
    throw new Error(`Encryption job failed: status=${encStatus}, error=${jobError}`)
  }

  // 截图加密任务执行结果
  await capture('sm4-ecb-encrypt-result', 1440, 1000)

  // 8. 验证解密单选联动
  await clickText('nav button', '算法工具')
  await until("!!document.querySelector('.search-bar input')", 'catalog loaded again')
  await evaluate(setInput('.search-bar input', 'sm4_ecb'))
  await until("[...document.querySelectorAll('.tool-card')].some(e=>e.querySelector('code')?.textContent==='sm4_ecb')", 'sm4_ecb card again')
  await evaluate("[...document.querySelectorAll('.tool-card')].find(e=>e.querySelector('code')?.textContent==='sm4_ecb').click()")
  await until("!!document.querySelector('.tool-form')", 'sm4_ecb form again')

  // 点击解密 radio
  await evaluate("(()=>{const r=document.querySelector('input[type=radio][value=decrypt]');r.click();r.dispatchEvent(new Event('change',{bubbles:true}));})()")
  const decCheckedAfter = await evaluate("document.querySelector('input[type=radio][value=decrypt]')?.checked")
  const encCheckedAfter = await evaluate("document.querySelector('input[type=radio][value=encrypt]')?.checked")
  if (!decCheckedAfter || encCheckedAfter) throw new Error(`Decryption mode toggle failed: dec=${decCheckedAfter}, enc=${encCheckedAfter}`)

  console.log('Real browser SM4 ECB encrypt form, random key generation, block size validation, task execution, and decrypt mutual exclusion verified successfully.')
  if (errors.length) throw new Error('Browser reported runtime exceptions: ' + errors.join(', '))
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
} finally {
  socket?.close()
  chrome?.kill('SIGTERM')
  await sleep(400)
  const target = resolve(profile)
  if (target.startsWith(resolve(tmpdir()) + '/gmssl-web-cdp-sm4-roundtrip-')) {
    await rm(target, { recursive: true, force: true })
  }
}
