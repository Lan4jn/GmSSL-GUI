import type { Parameter, Tool } from '../src/types'
export const parameter=(extra:Partial<Parameter>={}):Parameter=>({name:'value',flag:'-value',label:'参数',type:'STRING',required:false,description:'参数说明',...extra})
export const tool=(extra:Partial<Tool>={}):Tool=>({id:'test',command:'test',title:'测试工具',category:'digest',description:'测试',parameters:[],acceptsStdin:true,stdoutMediaType:'text/plain',stdoutFilename:'result.txt',sensitiveOutput:false,defaultTimeoutSeconds:30,maxTimeoutSeconds:300,adminOnly:false,stateful:false,verification:{status:'unverified',evidence:'尚未验证'},...extra})
