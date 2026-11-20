import { spawn, spawnSync } from 'node:child_process'
import { mkdir, readFile, writeFile, mkdtemp, rm } from 'node:fs/promises'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

const root = resolve(fileURLToPath(new URL('..', import.meta.url)))
const artifacts = join(root, 'tests/artifacts/ux-workflows')
const base = process.env.E2E_BASE_URL ?? 'http://127.0.0.1:5173'
const browserPath = process.env.CHROME_PATH ?? '/Applications/Google Chrome.app/Contents/MacOS/Google Chrome'
const env = { ...process.env }
const fullSan = process.env.E2E_FULL_SAN === '1'
const openssl = process.env.OPENSSL_PATH ?? '/opt/homebrew/bin/openssl'
const opensslVersion = spawnSync(openssl, ['version'], { encoding: 'utf8' })
if (opensslVersion.status !== 0) throw new Error('Required OpenSSL executable failed: ' + openssl)
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
const profile = await mkdtemp(join(tmpdir(), 'gmssl-web-cdp-ux-'))
let chrome, socket, nextId = 0
const pending = new Map(), errors = []
let consoleLeak = false
const results = []
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
  for (let i = 0; i < 600; i++) {
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
    } else if (msg.method === 'Runtime.consoleAPICalled') {
      const text = (msg.params.args || []).map(a => a.value || '').join(' ')
      if ((password && text.includes(password)) || /-----BEGIN|[0-9a-f]{32,}/i.test(text)) consoleLeak = true
    } else if (msg.method === 'Runtime.exceptionThrown') {
      errors.push('Uncaught browser runtime exception')
    }
  }

  await send('Runtime.enable')
  await send('Page.enable')
  await send('Emulation.setDeviceMetricsOverride', { width: 1440, height: 1000, deviceScaleFactor: 1, mobile: false })
  await send('Page.navigate', { url: base })
  await until("!!document.querySelector('.login-card')", 'login screen')

  if (!username || !password) throw new Error('Set E2E_ENV_FILE or E2E_USERNAME/E2E_PASSWORD for browser workflows')

  await evaluate(setInput('#username', username))
  await evaluate(setInput('#password', password))
  await evaluate("document.querySelector('.login-card form').requestSubmit()")
  await until("!!document.querySelector('.app-shell')", 'authenticated workspace')
  await until("!document.querySelector('.loading-line')", 'project loaded')


  await evaluate("window.__ux=[];window.__nativeFetch=window.fetch;window.fetch=async(...a)=>{const r=await window.__nativeFetch(...a);if(/(keys\\/generate|certificate-workflows|jobs)$/.test(String(a[0]))&&a[1]?.method==='POST'){const b=JSON.parse(a[1].body||'{}'),d=await r.clone().json();window.__ux.push({endpoint:String(a[0]),http:r.status,provider:b.provider,algorithm:b.algorithm,bits:b.bits,curve:b.curve,storage:b.storage,profile:b.profile,subject:b.subject,sanDns:b.sanDns,sanIps:b.sanIps,csrRef:b.csrRef,id:d.id,reference:d.reference,key:d.key,publicKey:d.publicKey,temporaryPublicKeyFile:d.temporaryPublicKeyFile,status:d.status,workflowId:d.workflowId,keys:d.keys,files:d.files,stages:d.stages,error:d.error,code:d.code,message:d.message})}return r}")
  const redact = s => String(s).replace(/[0-9a-f]{32,}/gi,'[redacted]')
  async function check(name, fn) {
    try { const evidence=await fn();results.push({name,status:'passed',evidence});console.log(name+': passed') }
    catch(e) { results.push({name,status:'failed',error:redact(e.message),traffic:await evaluate('window.__ux')});console.log(name+': failed: '+redact(e.message));await maskedCapture(name+'-failed') }
    await writeFile(join(artifacts,'summary.json'),JSON.stringify({timestamp:new Date().toISOString(),base,mode:fullSan?'dns-ip-csr-chain':'dns-keygen',openssl:opensslVersion.stdout.trim(),results},null,2))
  }
  async function maskedCapture(name) {
    await evaluate("document.querySelectorAll('input[type=password],.secret-input-wrap input,.revealed-passphrase,button[title=\"查看平台加密保存的私钥口令\"]').forEach(e=>e.style.visibility='hidden')")
    await capture(name)
  }
  async function fill(selector,value) {
    await until('!!document.querySelector('+JSON.stringify(selector)+')',selector)
    await evaluate('(()=>{const e=document.querySelector('+JSON.stringify(selector)+');e.value='+JSON.stringify(value)+';e.dispatchEvent(new Event(e.tagName===\'SELECT\'?\'change\':\'input\',{bubbles:true}))})()')
  }
  async function click(selector,text) {
    const q='[...document.querySelectorAll('+JSON.stringify(selector)+')].find(e=>e.textContent.trim().includes('+JSON.stringify(text)+'))'
    await until('!!('+q+') && !('+q+').disabled',text)
    await evaluate('('+q+').click()')
  }
  async function api(path) {
    return evaluate('(async()=>{const r=await fetch('+JSON.stringify('/api/v1'+path)+',{cache:"no-store"});if(!r.ok)throw Error("GET HTTP "+r.status);return r.json()})()')
  }
  async function openTool(id) {
    await click('nav button','算法工具')
    if(await evaluate("!!document.querySelector('.tool-detail')"))await click('.tool-detail button','返回工具目录')
    await fill('.search-bar input',id)
    const q='[...document.querySelectorAll(".tool-card")].find(e=>e.querySelector("code")?.textContent==='+JSON.stringify(id)+')'
    await until('!!('+q+')',id+' card');await evaluate('('+q+').click()')
    await until("!!document.querySelector('.tool-form')",id+' form')
  }
  async function generate(algorithm,provider,storage = 'MANAGED') {
    await until("!!document.querySelector('.key-generate-modal form') || !!document.querySelector('.key-generate-modal .error')",'capabilities loaded')
    const radio='input[name=keygen-provider][value='+provider+']'
    if(!await evaluate('!!document.querySelector('+JSON.stringify(radio)+') && !document.querySelector('+JSON.stringify(radio)+').disabled'))throw Error('Provider unavailable: '+provider)
    await evaluate('document.querySelector('+JSON.stringify(radio)+').click()')
    await fill('select[aria-label=算法选择]',algorithm)
    await evaluate('document.querySelector('+JSON.stringify('input[name=keygen-storage][value='+storage+']')+').click()')
    await click('.key-generate-modal button[type=submit]','立即生成密钥')
    await until("!document.querySelector('.key-generate-modal') || !!document.querySelector('.key-generate-modal .error')",'keygen response')
    const gen=await evaluate('window.__ux.at(-1)')
    if(!gen||gen.http!==200||await evaluate("!!document.querySelector('.key-generate-modal .error')"))throw Error('Keygen response: '+JSON.stringify(gen))
    return gen
  }
  if(process.env.E2E_PROJECT_ID)await fill('#project-switch',process.env.E2E_PROJECT_ID)
  await until("!!document.querySelector('#project-switch')?.value",'selected project')
  const pid=await evaluate("document.querySelector('#project-switch').value")
  await check('sm4-managed-encrypt',async()=>{
    await openTool('sm4_ecb');await click('.tool-form button','生成密钥 (SSL)')
    const gen=await generate('SM4','gmssl')
    await until("document.querySelector('.secret-input-wrap input')?.value.startsWith('key:')",'managed ref auto-fill')
    if(await evaluate("document.querySelector('.secret-input-wrap input').value")!==gen.reference)throw Error('Wrong generated key reference')
    await fill('.tool-form textarea','0123456789abcdef0123456789abcdef')
    await maskedCapture('sm4-managed-ref')
    await evaluate("document.querySelector('.tool-form').requestSubmit()")
    await until("!!document.querySelector('.job-detail .badge.good') || !!document.querySelector('.job-detail .badge.bad')",'encryption settled')
    const req=await evaluate('window.__ux.at(-1)'),job=await api('/projects/'+pid+'/jobs/'+req.id)
    if(job.status!=='SUCCEEDED')throw Error('Job '+job.id+' '+job.status+' '+redact(job.error||job.stderrPreview||''))
    await maskedCapture('sm4-encrypt-success')
    return {keyId:gen.key.id,provider:gen.provider,jobId:job.id,status:job.status}
  })

  for(const storage of ['MANAGED','TEMPORARY'])await check('sm2-'+storage.toLowerCase()+'-sign',async()=>{
    await openTool('sm2sign');await click('.tool-form button','生成密钥对 (SSL)')
    const gen=await generate('SM2','gmssl',storage)
    await until('!!document.querySelector(".managed-passphrase-notice")','managed credential auto association')
    if(await evaluate('document.querySelector("input[aria-label=私钥密码]")?.value || ""'))throw Error('Signing required a manual passphrase')
    await fill('.tool-form textarea','Chrome managed SM2 signing integration')
    await evaluate('document.querySelector(".tool-form").requestSubmit()')
    await until('!!document.querySelector(".job-detail .badge.good") || !!document.querySelector(".job-detail .badge.bad")','SM2 signing result')
    const req=await evaluate('window.__ux.at(-1)'),job=await api('/projects/'+pid+'/jobs/'+req.id)
    if(job.status!=='SUCCEEDED')throw Error('Job '+job.id+' '+job.status+' '+redact(job.error||job.stderrPreview||''))
    await maskedCapture('sm2-'+storage.toLowerCase()+'-sign-success')
    return {reference:gen.reference,storage,jobId:job.id,status:job.status,manualPassphrase:false}
  })
  for(const storage of ['MANAGED','TEMPORARY'])await check('sm2-public-'+storage,async()=>{
    await openTool('sm2verify');await click('.tool-form button','生成密钥对 (SSL)')
    const gen=await generate('SM2','gmssl',storage)
    const ref=storage==='MANAGED'?'key:'+gen.publicKey?.id:'file:'+gen.temporaryPublicKeyFile?.id
    await until('document.querySelector("select[aria-label=公钥文件]")?.value==='+JSON.stringify(ref),'public reference auto-fill')
    const materialId=ref.split(':')[1]
    const pem=await evaluate('(async()=>{const r=await fetch('+JSON.stringify('/api/v1/projects/'+pid+'/'+(storage==='MANAGED'?'keys':'files')+'/'+materialId+'/download')+');if(!r.ok)throw Error("Public download HTTP "+r.status);return r.text()})()')
    if(!pem.includes('-----BEGIN PUBLIC KEY-----')||pem.includes('PRIVATE KEY'))throw Error('Public parameter received wrong material')
    return {storage,reference:ref,publicKeyHeaderVerified:true}
  })
  for(const [algorithm,provider] of [['ZUC256','gmssl'],['P-384','openssl']])await check('vault-'+algorithm,async()=>{
    if(await evaluate("!!document.querySelector('.key-generate-modal')"))await click('.key-generate-modal button','取消')
    await click('nav button','密钥库');await click('.page-heading button','生成密钥 (SSL)')
    const gen=await generate(algorithm,provider)
    if(gen.algorithm!==(algorithm==='P-384'?'EC':'ZUC256')||(algorithm==='P-384'&&gen.curve!=='secp384r1'))throw Error('Wrong engine payload')
    const keys=await api('/projects/'+pid+'/keys'),key=keys.find(k=>k.id===gen.key?.id)
    if(!key||key.generationProvider!==provider)throw Error('API key source mismatch')
    await until('document.querySelector("main").textContent.includes('+JSON.stringify(key.name)+')','vault refresh')
    if(!await evaluate('document.querySelector("main").textContent.toLowerCase().includes('+JSON.stringify(provider)+')'))throw Error('UI source missing')
    await maskedCapture('vault-'+algorithm)
    return {keyId:key.id,algorithm:gen.algorithm,curve:gen.curve,provider:key.generationProvider}
  })
  for(const provider of ['gmssl','openssl'])await check('wizard-'+provider,async()=>{
    if(await evaluate("!!document.querySelector('.key-generate-modal')"))await click('.key-generate-modal button','取消')
    await click('nav button','证书')
    if(await evaluate("!!document.querySelector('.cert-wizard-panel')"))await click('.cert-wizard-panel > .panel-heading button','关闭向导')
    await click('button','打开证书快捷向导');await until("!!document.querySelector('.wizard-footer')",'wizard loaded')
    await click('.wizard-footer button','下一步')
    await fill('#subject-cn','ux-'+provider+'.example.test');await fill('#subject-o','Chrome UX Integration')
    await fill('#san-input','ux-'+provider+'.example.test\nlocalhost'+(fullSan?'\n192.0.2.23\n2001:db8::23':''))
    await click('.wizard-footer button','下一步');await fill('.provider-field select',provider)
    if(await evaluate("document.querySelector('#key-pass')?.value || ''"))throw Error('Unexpected manually entered passphrase')
    await click('.wizard-footer button','下一步')
    await fill('#cert-name','ux_'+provider+'_'+Date.now());await click('.wizard-footer button','开始签发证书')
    await until("!!document.querySelector('.execution-success') || !!document.querySelector('.execution-failure')",'workflow response')
    const wf=await evaluate('window.__ux.at(-1)')
    if(wf.status!=='SUCCEEDED'||!await evaluate("!!document.querySelector('.execution-success')"))throw Error('Workflow response: '+JSON.stringify(wf))
    if(!wf.keys?.some(k=>k.hasManagedPassphrase))throw Error('Managed credential DTO missing')
    if(!wf.keys.some(k=>k.generationProvider===provider))throw Error('Workflow did not retain requested provider source')
    const cert=wf.files.find(f=>f.name.endsWith('.pem'))||wf.files[0]
    const pem=await evaluate('(async()=>{const r=await fetch('+JSON.stringify('/api/v1/projects/'+pid+'/files/'+cert.id+'/download')+',{cache:"no-store"});if(!r.ok)throw Error("Download HTTP "+r.status);return r.text()})()')
    const x509=spawnSync(openssl,['x509','-noout','-subject','-ext','subjectAltName'],{input:pem,encoding:'utf8'})
    if(x509.status!==0||!x509.stdout.includes('ux-'+provider+'.example.test')||!x509.stdout.includes('DNS:localhost'))throw Error('Actual certificate CN/DNS SAN check failed: '+x509.stderr)
    if(fullSan && (!x509.stdout.includes('IP Address:192.0.2.23') || !x509.stdout.toUpperCase().includes('IP ADDRESS:2001:DB8:0:0:0:0:0:23')))throw Error('Actual certificate IPv4/IPv6 SAN missing: '+x509.stdout)
    await maskedCapture('wizard-'+provider+'-success');await click('.wizard-actions button','查看并完成')
    await until("!document.querySelector('.cert-wizard-panel') && !document.querySelector('.loading-line')",'workflow completion refreshed')
    await click('nav button','密钥库');await until('document.querySelector("main").textContent.includes('+JSON.stringify(cert.name)+')','certificate files refreshed')
    return {workflowId:wf.workflowId,certificateId:cert.id,status:wf.status,provider,decoded:x509.stdout.trim()}
  })

  if(fullSan)await check('wizard-csr-ca-chain',async()=>{
    async function startProfile(kind) {
      await click('nav button','证书')
      if(await evaluate("!!document.querySelector('.cert-wizard-panel')"))await click('.cert-wizard-panel > .panel-heading button','关闭向导')
      await click('button','打开证书快捷向导')
      const selector='input[name=cert-profile][value='+kind+']'
      await until('!!document.querySelector('+JSON.stringify(selector)+')','profile '+kind)
      await evaluate('document.querySelector('+JSON.stringify(selector)+').click()')
      await click('.wizard-footer button','下一步')
    }
    async function finishProfile(name) {
      await click('.wizard-footer button','下一步')
      await fill('#cert-name',name)
      await click('.wizard-footer button','开始签发证书')
      await until("!!document.querySelector('.execution-success') || !!document.querySelector('.execution-failure')",'profile '+name+' result')
      const wf=await evaluate('window.__ux.at(-1)')
      if(wf.status!=='SUCCEEDED')throw Error('Workflow response: '+JSON.stringify(wf))
      await maskedCapture(name+'-success')
      await click('.wizard-actions button','查看并完成')
      await until("!document.querySelector('.cert-wizard-panel') && !document.querySelector('.loading-line')",'profile material refresh')
      return wf
    }
    async function publicFile(file) {
      return evaluate('(async()=>{const r=await fetch('+JSON.stringify('/api/v1/projects/'+pid+'/files/'+file.id+'/download')+',{cache:"no-store"});if(!r.ok)throw Error("File HTTP "+r.status);return r.text()})()')
    }
    const stamp=Date.now()
    await startProfile('ROOT_CA')
    await fill('#subject-cn','Chrome UX Root CA')
    await click('.wizard-footer button','下一步')
    await fill('.provider-field select','gmssl')
    const root=await finishProfile('ux_root_'+stamp)
    const rootFile=root.files.find(f=>/\.pem$|\.crt$/.test(f.name))||root.files[0]
    const rootKey=root.keys.find(k=>k.keyKind==='PRIVATE_KEY')
    if(!rootKey?.hasManagedPassphrase)throw Error('CA credential not managed')
    await startProfile('CSR')
    await fill('#subject-cn','csr-ux.example.test')
    await fill('#san-input','csr-ux.example.test\nlocalhost\n192.0.2.24\n2001:db8::24')
    await click('.wizard-footer button','下一步')
    await fill('.provider-field select','gmssl')
    const csr=await finishProfile('ux_csr_'+stamp)
    const csrFile=csr.files.find(f=>/\.csr$|req/.test(f.name))||csr.files[0]
    const requestPem=await publicFile(csrFile)
    const req=spawnSync(openssl,['req','-noout','-text','-verify','-vfyopt','distid:1234567812345678'],{input:requestPem,encoding:'utf8'})
    if(req.status!==0||!(req.stdout+req.stderr).includes('self-signature verify OK'))throw Error('CSR signature verification failed: status='+req.status+' '+req.stderr)
    for(const expected of ['DNS:csr-ux.example.test','DNS:localhost','IP Address:192.0.2.24','IP Address:2001:DB8:0:0:0:0:0:24']) {
      if(!req.stdout.toUpperCase().includes(expected.toUpperCase()))throw Error('CSR missing SAN: '+expected)
    }
    await startProfile('CA_SIGN')
    if(await evaluate("document.querySelector('#subject-cn')?.value || ''"))throw Error('CA_SIGN should reuse CSR subject')
    if(await evaluate("document.querySelector('#san-input')?.value || ''"))throw Error('CA_SIGN must not require SAN re-entry')
    await click('.wizard-footer button','下一步')
    await fill('#csr-file','file:'+csrFile.id)
    await fill('#issuer-cert','file:'+rootFile.id)
    await fill('#issuer-key','key:'+rootKey.id)
    await until("!!document.querySelector('.notice-managed')",'managed issuer credential')
    if(await evaluate("!!document.querySelector('#issuer-pass')"))throw Error('CA demanded manual managed passphrase')
    const leaf=await finishProfile('ux_issued_'+stamp)
    if(leaf.sanDns?.length || leaf.sanIps?.length)throw Error('CA_SIGN sent SAN instead of inheriting CSR')
    if(leaf.csrRef!=='file:'+csrFile.id)throw Error('CA_SIGN did not use selected CSR reference')
    const leafFile=leaf.files.find(f=>/\.pem$|\.crt$/.test(f.name))||leaf.files[0]
    const leafPem=await publicFile(leafFile)
    const cert=spawnSync(openssl,['x509','-noout','-subject','-ext','subjectAltName'],{input:leafPem,encoding:'utf8'})
    if(cert.status!==0)throw Error('Issued certificate parser failed: '+cert.stderr)
    for(const expected of ['csr-ux.example.test','DNS:localhost','IP Address:192.0.2.24','IP Address:2001:DB8:0:0:0:0:0:24']) {
      if(!cert.stdout.toUpperCase().includes(expected.toUpperCase()))throw Error('CA_SIGN lost CSR SAN: '+expected)
    }
    const rootPath=join(artifacts,'chain-root-public.pem'),leafPath=join(artifacts,'chain-leaf-public.pem')
    await writeFile(rootPath,await publicFile(rootFile));await writeFile(leafPath,leafPem)
    const verify=spawnSync(openssl,['verify','-CAfile',rootPath,'-vfyopt','distid:1234567812345678',leafPath],{encoding:'utf8'})
    if(verify.status!==0)throw Error('Issued chain verify failed: '+verify.stderr)
    await click('nav button','密钥库')
    await until('document.querySelector("main").textContent.includes('+JSON.stringify(leafFile.name)+')','issued file UI refresh')
    return {rootWorkflowId:root.workflowId,csrWorkflowId:csr.workflowId,issuedWorkflowId:leaf.workflowId,csrSignature:'verified',csrFileId:csrFile.id,issuedFileId:leafFile.id,certificate:cert.stdout.trim(),chain:verify.stdout.trim()}
  })
  await check('privacy-and-errors',async()=>{
    const stored=await evaluate('JSON.stringify({local:{...localStorage},session:{...sessionStorage}})')
    if(stored.includes(password)||/passphrase|private.?key|valueHex|csrf|token/i.test(stored))throw Error('Sensitive browser storage detected')
    if(consoleLeak)throw Error('Plaintext credential or key detected in browser console')
    if(errors.length)throw Error('Browser runtime exceptions detected')
    if(await evaluate('!!document.querySelector("main > .banner.error")'))throw Error('Workspace error banner present')
    return {storage:JSON.parse(stored),runtimeErrorCount:errors.length,consoleLeak}
  })
  if(results.some(r=>r.status==='failed'))process.exitCode=1
} catch (error) {
  const message=error.message.replace(/[0-9a-f]{32,}/gi,'[redacted]')
  console.error(message)
  results.push({name:'setup-or-harness',status:'failed',error:message})
  await writeFile(join(artifacts,'summary.json'),JSON.stringify({timestamp:new Date().toISOString(),base,results},null,2))
  process.exitCode = 1
} finally {
  socket?.close();chrome?.kill('SIGTERM');await sleep(400)
  if(resolve(profile).startsWith(resolve(tmpdir())+'/gmssl-web-cdp-ux-'))await rm(profile,{recursive:true,force:true})
}
