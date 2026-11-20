import { describe, it, expect, vi, beforeEach } from 'vitest'
import { request, session, setCsrfToken, ApiError, errorMessage } from '../src/api'
beforeEach(()=>{setCsrfToken('');vi.restoreAllMocks();vi.stubGlobal('localStorage',{setItem:vi.fn(),getItem:vi.fn()});vi.stubGlobal('sessionStorage',{setItem:vi.fn(),getItem:vi.fn()})})
describe('same-origin API and error contract',()=>{
 it('keeps session CSRF in memory and includes it only on mutations',async()=>{
  const fetch=vi.fn().mockResolvedValueOnce(new Response(JSON.stringify({user:{id:'a'},csrfToken:'memory-token'}),{status:200})).mockResolvedValueOnce(new Response(null,{status:204})).mockResolvedValueOnce(new Response('[]'))
  vi.stubGlobal('fetch',fetch);await session('/auth/login',{username:'u',password:'p'});await request('/projects',{method:'POST',body:'{}'});await request('/projects')
  expect(fetch.mock.calls[0][1].credentials).toBe('same-origin')
  expect(fetch.mock.calls[0][1].headers.has('X-CSRF-Token')).toBe(false)
  expect(fetch.mock.calls[1][1].headers.get('X-CSRF-Token')).toBe('memory-token')
  expect(fetch.mock.calls[2][1].headers.has('X-CSRF-Token')).toBe(false)
  expect(localStorage.setItem).not.toHaveBeenCalled();expect(sessionStorage.setItem).not.toHaveBeenCalled()
 })
 it('does not override multipart boundary',async()=>{
  const fetch=vi.fn().mockResolvedValue(new Response('{}'));vi.stubGlobal('fetch',fetch);const form=new FormData();form.append('file',new File(['abc'],'a.txt'));await request('/files',{method:'POST',body:form});expect(fetch.mock.calls[0][1].headers.has('Content-Type')).toBe(false)
 })
 it('preserves server errors and request correlation',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response(JSON.stringify({code:'FORBIDDEN',message:'项目权限不足',requestId:'trace-1'}),{status:403})))
  try{await request('/projects')}catch(e){expect(e).toBeInstanceOf(ApiError);expect(errorMessage(e)).toBe('项目权限不足 · 请求 trace-1')}
 })
 it('handles non-JSON proxy errors and network failures',async()=>{
  vi.stubGlobal('fetch',vi.fn().mockResolvedValue(new Response('<html>',{status:502})));await expect(request('/projects')).rejects.toMatchObject({status:502,code:'HTTP_502'})
  vi.stubGlobal('fetch',vi.fn().mockRejectedValue(new Error('offline')));await expect(request('/projects')).rejects.toMatchObject({status:0,code:'NETWORK_ERROR'})
 })
 it('expires unauthorized sessions and clears CSRF',async()=>{
  setCsrfToken('expired');const listener=vi.fn();window.addEventListener('session-expired',listener)
  const fetch=vi.fn().mockResolvedValueOnce(new Response('{}',{status:401})).mockResolvedValueOnce(new Response(null,{status:204}));vi.stubGlobal('fetch',fetch)
  await expect(request('/auth/me')).rejects.toMatchObject({status:401});await request('/auth/logout',{method:'POST'});expect(listener).toHaveBeenCalledOnce();expect(fetch.mock.calls[1][1].headers.get('X-CSRF-Token')).toBe('');window.removeEventListener('session-expired',listener)
 })
})
