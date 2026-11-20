import type { Artifact, Tool } from './types'
export function canDownloadArtifact(artifact: Artifact, tool: Tool | undefined): boolean {
  if (artifact.statefulPrivate || artifact.downloadable === false) return false
  if (artifact.downloadable === true) return true
  return !!tool && !tool.stateful && !['lmskeygen','hsskeygen','xmsskeygen','xmssmtkeygen'].includes(tool.command)
}
export function canPromoteArtifact(artifact: Artifact, tool: Tool | undefined): boolean {
  if (artifact.promotable !== undefined) return artifact.promotable
  if (artifact.statefulPrivate) {
    return !!tool && ['lmskeygen','hsskeygen','xmsskeygen','xmssmtkeygen'].includes(tool.command)
  }
  return !!tool && !tool.stateful && !['lmskeygen','hsskeygen','xmsskeygen','xmssmtkeygen'].includes(tool.command)
}
