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
await mkdir(artifacts, { recursive:true })
const profile = await mkdtemp(join(tmpdir(), 'gmssl-web-cdp-'))
let chrome, vite, socket, nextId=0
const pending=new Map(),errors=[]
const sleep=ms=>new Promise(r=>setTimeout(r,ms))
const send=(method,params={})=>new Promise((resolve,reject)=>{
  const id=++nextId; const timer=setTimeout(()=>{pending.delete(id);reject(new Error(`CDP timeout: ${method}`))},15000)
  pending.set(id,{resolve:v=>{clearTimeout(timer);resolve(v)},reject:e=>{clearTimeout(timer);reject(e)}})
  socket.send(JSON.stringify({id,method,params}))
})
async function evaluate(expression){ const result=await send('Runtime.evaluate',{expression,returnByValue:true,awaitPromise:true});if(result.exceptionDetails)throw new Error('Browser expression failed (expression omitted to protect credentials)');return result.result.value }
async function until(expression,label){for(let i=0;i<200;i++){if(await evaluate(expression))return;await sleep(150)}throw new Error(`UI timeout: ${label}`)}
async function capture(name,width=1440,height=1000){await send('Emulation.setDeviceMetricsOverride',{width,height,deviceScaleFactor:1,mobile:width<720});await sleep(250);const shot=await send('Page.captureScreenshot',{format:'png',captureBeyondViewport:false});await writeFile(join(artifacts,`${name}.png`),Buffer.from(shot.data,'base64'));const overflow=await evaluate('document.documentElement.scrollWidth>window.innerWidth');if(overflow)throw new Error(`Horizontal overflow: ${name}`)}
const setInput=(selector,value)=>`(()=>{const e=document.querySelector(${JSON.stringify(selector)});Object.getOwnPropertyDescriptor(HTMLInputElement.prototype,'value').set.call(e,${JSON.stringify(value)});e.dispatchEvent(new Event('input',{bubbles:true}))})()`
async function clickText(selector,text){return evaluate(`(()=>{const e=[...document.querySelectorAll(${JSON.stringify(selector)})].find(e=>e.textContent.trim()===${JSON.stringify(text)});if(!e)throw Error('missing target');e.click()})()`)}
try {
  if (process.env.START_WEB==='1') {
    vite=spawn(process.execPath,['node_modules/vite/bin/vite.js','--host','127.0.0.1','--port','5173','--strictPort'],{cwd:root,stdio:'ignore'});
    for(let i=0;i<40;i++){try{const r=await fetch(base);if(r.ok)break}catch{}await sleep(200)}
  }
  if(!(await fetch(base)).ok)throw new Error('Frontend is not ready')
  chrome=spawn(browserPath,['--headless','--disable-gpu','--no-first-run','--no-default-browser-check',`--user-data-dir=${profile}`,'--remote-debugging-port=0','about:blank'],{stdio:'ignore'})
  let port
  for(let i=0;i<60;i++){try{port=(await readFile(join(profile,'DevToolsActivePort'),'utf8')).split('\n')[0];break}catch{await sleep(150)}}
  if(!port)throw new Error('Chrome CDP failed to start')
  const targets=await (await fetch(`http://127.0.0.1:${port}/json/list`)).json(),target=targets.find(t=>t.type==='page')
  socket=new WebSocket(target.webSocketDebuggerUrl)
  await new Promise((resolve,reject)=>{socket.onopen=resolve;socket.onerror=reject})
  socket.onmessage=event=>{const msg=JSON.parse(event.data);if(msg.id){const p=pending.get(msg.id);if(!p)return;pending.delete(msg.id);msg.error?p.reject(new Error('CDP operation failed')):p.resolve(msg.result)}else if(msg.method==='Runtime.exceptionThrown')errors.push('Uncaught browser runtime exception')}
  await send('Runtime.enable');await send('Page.enable');await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false});await send('Page.navigate',{url:base});await until("!!document.querySelector('.login-card')",'login screen');await capture('login-desktop');await capture('login-mobile',390,844)
  if (username && password) {
    await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false})
    await evaluate(setInput('#username',username));await evaluate(setInput('#password',password));await evaluate("document.querySelector('.login-card form').requestSubmit()")
    await until("!!document.querySelector('.app-shell')",'authenticated workspace');await until("!document.querySelector('.loading-line')",'project loaded')
    if (await evaluate("!!document.querySelector('.banner.error')"))throw new Error('Authenticated workspace contains API error')
    await capture('workspace-desktop');await capture('workspace-mobile',390,844);await send('Emulation.setDeviceMetricsOverride',{width:1440,height:1000,deviceScaleFactor:1,mobile:false})
    if (!await evaluate("!!document.querySelector('#project-switch option[value]:not([value=\"\"])')")) {
      await clickText('.page-heading button','创建项目');await evaluate(setInput('.modal input','浏览器验收项目'));await evaluate("document.querySelector('.modal form').requestSubmit()");await until("!document.querySelector('.modal')",'project creation')
    }
    await clickText('nav button','算法工具');await until("!!document.querySelector('.search-bar input')",'catalog');await evaluate(setInput('.search-bar input','sm3'));await until("[...document.querySelectorAll('.tool-card')].some(e=>e.querySelector('code')?.textContent==='sm3')",'SM3 capability')
    await evaluate("[...document.querySelectorAll('.tool-card')].find(e=>e.querySelector('code')?.textContent==='sm3').click()");await until("!!document.querySelector('.tool-form textarea')",'SM3 form');await capture('sm3-form')
    if (process.env.E2E_SKIP_NATIVE!=='1') {
    await evaluate("(()=>{const e=document.querySelector('.tool-form textarea');Object.getOwnPropertyDescriptor(HTMLTextAreaElement.prototype,'value').set.call(e,'abc');e.dispatchEvent(new Event('input',{bubbles:true}));})()");await evaluate("document.querySelector('.tool-form').requestSubmit()")
    await until("!!document.querySelector('.job-detail .badge.good')",'SM3 terminal success');await until("document.querySelector('.job-detail')?.textContent.includes('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')",'SM3 known answer');await capture('sm3-result')
    }
    const storage=await evaluate('({local:localStorage.length,session:sessionStorage.length})');if(storage.local||storage.session)throw new Error('Unexpected persistent browser storage')
    const shots=['login-desktop','login-mobile','workspace-desktop','workspace-mobile','sm3-form']
    if(process.env.E2E_SKIP_NATIVE!=='1')shots.push('sm3-result')
    await writeFile(join(artifacts,'browser-summary.json'),JSON.stringify({mode:'real-api',login:true,project:true,sm3Kat:process.env.E2E_SKIP_NATIVE!=='1',storageEmpty:true,runtimeErrors:errors,screenshots:shots},null,2))
    console.log(process.env.E2E_SKIP_NATIVE==='1'?'Real browser login → project → catalog → SM3 form passed; native execution intentionally skipped.':'Real browser login → project → SM3 abc KAT passed; screenshots saved. No credentials logged.')
  }else {await writeFile(join(artifacts,'browser-summary.json'),JSON.stringify({mode:'login-only',backendTested:false,screenshots:['login-desktop','login-mobile'],runtimeErrors:errors},null,2));console.log('Real desktop/mobile login render verified; backend not tested (no test credentials supplied).')}
  if(errors.length)throw new Error('Browser reported runtime exceptions')
} catch(error){console.error(error.message);process.exitCode=1}
finally {socket?.close();chrome?.kill('SIGTERM');vite?.kill('SIGTERM');await sleep(400);const target=resolve(profile);if(target.startsWith(resolve(tmpdir())+'/gmssl-web-cdp-'))await rm(target,{recursive:true,force:true})}
