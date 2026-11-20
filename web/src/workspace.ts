import { computed, ref, onMounted, onUnmounted } from 'vue'
import { ApiError, request, post, session, setCsrfToken, errorMessage, download } from './api'
import type { User, Project, Catalog, Key, ManagedFile, Job, Member, Audit } from './types'
import { canManage, canEdit } from './forms'
export function useWorkspace(){
  const user=ref<User|null>(null), booting=ref(true), busy=ref(false), loading=ref(false), error=ref(''), success=ref('')
  const projects=ref<Project[]>([]), projectId=ref(''), catalog=ref<Catalog|null>(null), catalogError=ref(''), dataError=ref('')
  const keys=ref<Key[]>([]), files=ref<ManagedFile[]>([]), jobs=ref<Job[]>([]), members=ref<Member[]>([]), users=ref<User[]>([]), audit=ref<Audit[]>([])
  const ready=ref(false), page=ref('dashboard'), selectedJob=ref<Job|null>(null), mobileNav=ref(false)
  let generation=0, poll: ReturnType<typeof setTimeout>|undefined
  const project=computed(()=>projects.value.find(p=>p.id===projectId.value)), manager=computed(()=>canManage(user.value,project.value)), editor=computed(()=>canEdit(user.value,project.value))
  const prefix=computed(()=>`/projects/${projectId.value}`)
  function clearProject(){keys.value=[];files.value=[];jobs.value=[];members.value=[];audit.value=[];selectedJob.value=null;ready.value=false;dataError.value=''}
  function expire(){generation++;user.value=null;setCsrfToken('');projects.value=[];projectId.value='';clearProject();catalog.value=null;users.value=[];success.value='';error.value='会话已结束，请重新登录。';clearTimeout(poll)}
  async function act(fn:()=>Promise<void>){ if(busy.value)return;busy.value=true;error.value='';success.value='';try{await fn()}catch(e){error.value=errorMessage(e)}finally{busy.value=false} }
  async function loadCatalog(){try{catalog.value=await request<Catalog>('/capabilities');catalogError.value=''}catch(e){catalogError.value=errorMessage(e)}}
  async function loadProject(id=projectId.value){
    const token=++generation;clearProject();loading.value=true
    if(!id){loading.value=false;return}
    try{const base=`/projects/${id}`;const [k,f,j]=await Promise.all([request<Key[]>(`${base}/keys`),request<ManagedFile[]>(`${base}/files`),request<Job[]>(`${base}/jobs`)]);if(token!==generation)return;keys.value=k;files.value=f;jobs.value=j;ready.value=true;await loadAdmin(token)}catch(e){if(token===generation)dataError.value=errorMessage(e)}finally{if(token===generation)loading.value=false}
  }
  async function loadAdmin(token=generation){if(!projectId.value || !manager.value)return;const base=prefix.value;try{const [m,a]=await Promise.all([request<Member[]>(`${base}/members`),request<Audit[]>(`${base}/audit`)]);if(token===generation){members.value=m;audit.value=a}}catch(e){if(token===generation)error.value=errorMessage(e)}}
  async function loadUsers(){if(user.value?.role==='ADMIN')users.value=await request<User[]>('/users')}
  async function initialize(){await Promise.all([loadCatalog(),(async()=>{projects.value=await request<Project[]>('/projects');projectId.value=projects.value[0]?.id??'';await loadProject()})(),loadUsers()])}
  async function login(username:string,password:string){await act(async()=>{const s=await session('/auth/login',{username,password});user.value=s.user;await initialize();clearTimeout(poll);void tick()})}
  async function logout(){await act(async()=>{await post('/auth/logout');expire();error.value=''})}
  async function switchProject(id:string){if(busy.value||loading.value)return;projectId.value=id;if(['audit','projects'].includes(page.value)&&!manager.value)page.value='dashboard';await loadProject(id)}
  async function refresh(){await act(async()=>{await Promise.all([loadCatalog(),loadProject(),loadUsers()])})}
  async function createProject(name:string,description:string){const created=await post<Project>('/projects',{name,description});projects.value=await request<Project[]>('/projects');projectId.value=created.id;await loadProject(created.id);success.value='项目已创建'}
  async function runJob(body:unknown){const id=projectId.value;await act(async()=>{const job=await post<Job>(`/projects/${id}/jobs`,body);if(id===projectId.value){jobs.value=[job,...jobs.value.filter(j=>j.id!==job.id)];selectedJob.value=job;page.value='jobs'}success.value='任务已提交，等待引擎实际执行'})}
  async function upload(file:File,temporary=false){if(file.size>16*1024*1024)throw new Error('单个文件最大 16 MiB');const id=projectId.value;const form=new FormData();form.append('file',file);if(temporary)form.append('temporary','true');const f=await request<ManagedFile>(`/projects/${id}/files`,{method:'POST',body:form});if(id===projectId.value)files.value=[f,...files.value];return f}
  async function inspectJob(job:Job){const token=generation,base=prefix.value;await act(async()=>{const detail=await request<Job>(`${base}/jobs/${job.id}`);if(token===generation){selectedJob.value=detail;if(!['RUNNING','QUEUED'].includes(detail.status)){const refreshedFiles=await request<ManagedFile[]>(`${base}/files`);if(token===generation)files.value=refreshedFiles}}})}
  async function cancel(job:Job){await act(async()=>{await post(`${prefix.value}/jobs/${job.id}/cancel`);const detail=await request<Job>(`${prefix.value}/jobs/${job.id}`);jobs.value=jobs.value.map(j=>j.id===detail.id?detail:j);if(selectedJob.value?.id===job.id)selectedJob.value=detail;const refreshedFiles=await request<ManagedFile[]>(`${prefix.value}/files`);files.value=refreshedFiles;success.value='取消请求已发送；以任务实际状态为准'})}
  async function fetchDownload(path:string,name:string){await act(async()=>{await download(path,name)})}
  async function tick(){if(user.value&&projectId.value&&jobs.value.some(j=>['RUNNING','QUEUED'].includes(j.status))&&!loading.value){const token=generation,base=prefix.value;try{const data=await request<Job[]>(`${base}/jobs`);if(token===generation){const hadActive=jobs.value.some(j=>['RUNNING','QUEUED'].includes(j.status));jobs.value=data;if(selectedJob.value)selectedJob.value=data.find(j=>j.id===selectedJob.value?.id)??selectedJob.value;const stillActive=data.some(j=>['RUNNING','QUEUED'].includes(j.status));if(hadActive&&!stillActive){const refreshedFiles=await request<ManagedFile[]>(`${base}/files`);if(token===generation)files.value=refreshedFiles}}}catch(e){if(token===generation)error.value=errorMessage(e)}}poll=setTimeout(tick,2000)}
  onMounted(async()=>{window.addEventListener('session-expired',expire);try{const s=await session('/auth/me');user.value=s.user;await initialize()}catch(e){if(!(e instanceof ApiError&&e.status===401))error.value=errorMessage(e);else error.value=''}finally{booting.value=false;void tick()}})
  onUnmounted(()=>{clearTimeout(poll);window.removeEventListener('session-expired',expire)})
  return {user,booting,busy,loading,error,success,projects,projectId,project,catalog,catalogError,dataError,keys,files,jobs,members,users,audit,ready,page,selectedJob,mobileNav,manager,editor,prefix,act,login,logout,switchProject,refresh,createProject,runJob,upload,inspectJob,cancel,fetchDownload,loadProject,loadAdmin,loadUsers}
}
