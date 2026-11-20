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
const profile = await mkdtemp(join(tmpdir(), 'gmssl-web-cdp-sm4-'))
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
  if (result.exceptionDetails) throw new Error('Browser expression failed (credentials protected)')
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
async function clickText(selector, text) {
  return evaluate(`(()=>{const e=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.trim()===${JSON.stringify(text)});if(!e)throw Error('missing target');e.click()})()`)
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

  // 进入算法工具目录并搜索 sm4_cbc
  await clickText('nav button', '算法工具')
  await until("!!document.querySelector('.search-bar input')", 'catalog loaded')
  await evaluate(setInput('.search-bar input', 'sm4_cbc'))
  await until("[...document.querySelectorAll('.tool-card')].some(e=>e.querySelector('code')?.textContent==='sm4_cbc')", 'sm4_cbc card')
  await evaluate("[...document.querySelectorAll('.tool-card')].find(e=>e.querySelector('code')?.textContent==='sm4_cbc').click()")
  await until("!!document.querySelector('.tool-form')", 'sm4_cbc form')

  // 验证「随机生成密钥」按钮存在
  await until("[...document.querySelectorAll('.tool-form button')].some(b=>b.textContent.includes('随机生成密钥'))", 'gen key button')

  // 点击生成密钥
  await evaluate("(()=>{const b=[...document.querySelectorAll('.tool-form button')].find(b=>b.textContent.includes('随机生成密钥'));b.click();})()")

  // 验证生成的提示文案与 32-hex 密钥填入
  await until("document.querySelector('.key-gen-notice')?.textContent.includes('已生成 128 位随机密钥')", 'key gen notice')
  await until("[...document.querySelectorAll('.tool-form button')].some(b=>b.textContent.includes('覆盖生成随机密钥'))", 'overwrite button text')

  const hexLength = await evaluate("(()=>{const i=document.querySelector('.secret-input-wrap input');return i?.value?.length;})()")
  if (hexLength !== 32) throw new Error(`Generated key length unexpected: expected 32 hex chars, got ${hexLength}`)

  // 点击显示明文
  await evaluate("(()=>{const b=document.querySelector('.reveal-button');if(b)b.click();})()")
  await until("document.querySelector('.reveal-button')?.textContent==='隐藏'", 'reveal plain text')

  // 截图前按安全规范遮蔽实际明文 key：设置模糊滤镜，同时保留 UI 结构与长度示意
  await evaluate("(()=>{const input=document.querySelector('.secret-input-wrap input');if(input){input.style.filter='blur(6px)';}})()")

  await capture('sm4-keygen-desktop', 1440, 1000)

  console.log('Real browser SM4 key generation verified; 128-bit key populated and masked screenshot saved.')
  if (errors.length) throw new Error('Browser reported runtime exceptions: ' + errors.join(', '))
} catch (error) {
  console.error(error.message)
  process.exitCode = 1
} finally {
  socket?.close()
  chrome?.kill('SIGTERM')
  await sleep(400)
  const target = resolve(profile)
  if (target.startsWith(resolve(tmpdir()) + '/gmssl-web-cdp-sm4-')) {
    await rm(target, { recursive: true, force: true })
  }
}
