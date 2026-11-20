import { describe, it, expect } from 'vitest'
import { canDownloadArtifact, canPromoteArtifact } from '../src/artifacts'
import { tool } from './fixtures'
const artifact={id:'a',name:'anything',size:12,mediaType:'application/octet-stream',sensitive:true}
describe('artifact single-authority controls',()=>{
 it('always forbids raw download of explicit stateful private material',()=>{
  expect(canDownloadArtifact({...artifact,statefulPrivate:true,downloadable:true},tool())).toBe(false)
  expect(canDownloadArtifact({...artifact,downloadable:false},tool())).toBe(false)
 })
 it('respects server promotion flags including consumed tombstone',()=>{
  expect(canPromoteArtifact({...artifact,statefulPrivate:true,promotable:true},tool({command:'xmsskeygen'}))).toBe(true)
  expect(canPromoteArtifact({...artifact,statefulPrivate:true,promotable:false},tool({command:'xmsskeygen'}))).toBe(false)
 })
 it('fails closed for old stateful keygen/signing responses and unknown tools',()=>{
  for(const command of ['lmskeygen','hsskeygen','xmsskeygen','xmssmtkeygen']){expect(canDownloadArtifact(artifact,tool({command}))).toBe(false);expect(canPromoteArtifact(artifact,tool({command}))).toBe(false)}
  expect(canDownloadArtifact(artifact,tool({stateful:true}))).toBe(false)
  expect(canPromoteArtifact(artifact,undefined)).toBe(false)
 })
 it('permits explicit public artifacts without filename guessing',()=>{
  expect(canDownloadArtifact({...artifact,downloadable:true,statefulPrivate:false},tool({command:'xmsskeygen'}))).toBe(true)
  expect(canDownloadArtifact(artifact,tool())).toBe(true)
 })
})
