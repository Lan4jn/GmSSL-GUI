<script setup lang="ts">
import { ref } from 'vue'
import {
  FileKey2,
  Boxes,
  ArrowRight,
  ArrowLeft
} from 'lucide-vue-next'
import type { Key, ManagedFile } from '../types'
import CertificateWizard from './CertificateWizard.vue'

withDefaults(
  defineProps<{
    projectId: string
    keys: Key[]
    files: ManagedFile[]
    disabled: boolean
  }>(),
  {
    keys: () => [],
    files: () => [],
    disabled: false
  }
)

const emit = defineEmits<{
  (e: 'navigate-vault'): void
  (e: 'refresh'): void
}>()

// 当前激活的场景：null 为主页卡片列表，'cert' 为制作证书向导
const activeScene = ref<string | null>(null)
</script>

<template>
  <div class="simple-workbench">
    <!-- 顶部状态与欢迎横幅 -->
    <div v-if="!activeScene" class="workbench-hero">
      <div class="hero-content">
        <span class="eyebrow-pill">快捷模式 · 零配置即用</span>
        <h2>快捷安全密码任务</h2>
        <p>为高频安全作业提供一步直达的场景向导，无需繁琐底层 CLI 参数与手动步骤拼接。</p>
      </div>

      <!-- 首屏居中突出展示制作证书向导大任务卡 -->
      <div class="primary-cert-card">
        <div class="cert-card-icon">
          <FileKey2 :size="36" />
        </div>
        <div class="cert-card-body">
          <div class="cert-card-tag">首要向导 · 一键全流程</div>
          <h3>制作国密 / X.509 证书</h3>
          <p>自动完成「私钥生成 → CSR 构建 → CA 证书签发 → 链组装」，首屏一键进入直达最终证书与证书链下载。</p>
        </div>
        <div class="cert-card-action">
          <button
            type="button"
            class="button primary large start-cert-btn"
            :disabled="disabled"
            @click="activeScene = 'cert'"
          >
            <span>开始制作证书</span>
            <ArrowRight :size="18" />
          </button>
        </div>
      </div>
    </div>

    <!-- 核心证书场景卡片网格 -->
    <div v-if="!activeScene" class="cards-grid">
      <!-- 1. 制作证书 -->
      <div class="task-card" @click="activeScene = 'cert'">
        <div class="card-icon cert-icon">
          <FileKey2 :size="24" />
        </div>
        <div class="card-content">
          <h4>制作证书</h4>
          <p>自签名服务证书或基于已有 CA 签发，全自动串联无缝签发并下载。</p>
        </div>
        <div class="card-footer">
          <button type="button" class="button small secondary card-btn" @click.stop="activeScene = 'cert'">打开证书向导 ↗</button>
        </div>
      </div>

      <!-- 2. 我的材料库 -->
      <div class="task-card" @click="emit('navigate-vault')">
        <div class="card-icon vault-icon">
          <Boxes :size="24" />
        </div>
        <div class="card-content">
          <h4>我的材料库</h4>
          <p>集中查看项目中已托管的所有私钥、公钥、证书与待处理输入材料。</p>
        </div>
        <div class="card-footer">
          <button type="button" class="button small secondary card-btn" @click.stop="emit('navigate-vault')">前往材料库 ↗</button>
        </div>
      </div>
    </div>

    <!-- 制作证书向导场景 -->
    <div v-else-if="activeScene === 'cert'" class="simple-wizard-container">
      <div class="scene-header">
        <button type="button" class="button small secondary" @click="activeScene = null">
          <ArrowLeft :size="16" />
          <span>返回任务列表</span>
        </button>
        <span class="scene-title">证书制作向导</span>
      </div>
      <CertificateWizard
        :project-id="projectId"
        :keys="keys"
        :files="files"
        :disabled="disabled"
        :simple-mode="true"
        @close="activeScene = null"
        @complete="emit('refresh'); activeScene = null"
        @navigate-vault="emit('navigate-vault'); activeScene = null"
      />
    </div>
  </div>
</template>

<style scoped>
.simple-workbench {
  display: flex;
  flex-direction: column;
  gap: 1.5rem;
}

.workbench-hero {
  display: flex;
  flex-direction: column;
  gap: 1.25rem;
  background: linear-gradient(135deg, #f0fdf4 0%, #ecfdf5 50%, #f0f9ff 100%);
  border: 1px solid #bbf7d0;
  border-radius: 12px;
  padding: 1.5rem;
}

.hero-content h2 {
  font-size: 1.5rem;
  font-weight: 700;
  color: #065f46;
  margin: 0.25rem 0;
}

.hero-content p {
  color: #047857;
  font-size: 0.9rem;
  margin: 0;
}

.eyebrow-pill {
  display: inline-block;
  font-size: 0.75rem;
  font-weight: 600;
  color: #059669;
  background: #d1fae5;
  padding: 0.2rem 0.6rem;
  border-radius: 9999px;
  margin-bottom: 0.25rem;
}

.primary-cert-card {
  display: flex;
  align-items: center;
  gap: 1.25rem;
  background: #ffffff;
  border: 2px solid #10b981;
  box-shadow: 0 4px 12px rgba(16, 185, 129, 0.12);
  border-radius: 10px;
  padding: 1.25rem;
}

.cert-card-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 56px;
  height: 56px;
  background: #ecfdf5;
  color: #059669;
  border-radius: 10px;
  flex-shrink: 0;
}

.cert-card-body {
  flex-grow: 1;
}

.cert-card-tag {
  font-size: 0.7rem;
  font-weight: 700;
  text-transform: uppercase;
  color: #059669;
  letter-spacing: 0.5px;
}

.cert-card-body h3 {
  font-size: 1.15rem;
  font-weight: 700;
  color: #0f172a;
  margin: 0.15rem 0 0.35rem;
}

.cert-card-body p {
  font-size: 0.85rem;
  color: #475569;
  margin: 0;
  line-height: 1.4;
}

.start-cert-btn {
  display: flex;
  align-items: center;
  gap: 0.5rem;
  white-space: nowrap;
}

.cards-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(280px, 1fr));
  gap: 1.25rem;
}

.task-card {
  display: flex;
  flex-direction: column;
  background: #ffffff;
  border: 1px solid #e2e8f0;
  border-radius: 10px;
  padding: 1.25rem;
  cursor: pointer;
  transition: transform 0.15s ease, box-shadow 0.15s ease, border-color 0.15s ease;
}

.task-card:hover {
  transform: translateY(-2px);
  box-shadow: 0 6px 16px rgba(0, 0, 0, 0.06);
  border-color: #cbd5e1;
}

.card-icon {
  display: flex;
  align-items: center;
  justify-content: center;
  width: 44px;
  height: 44px;
  border-radius: 8px;
  margin-bottom: 0.75rem;
}

.cert-icon { background: #ecfdf5; color: #059669; }
.vault-icon { background: #f8fafc; color: #475569; }

.card-content {
  flex-grow: 1;
  margin-bottom: 1rem;
}

.card-content h4 {
  font-size: 1rem;
  font-weight: 600;
  color: #0f172a;
  margin: 0 0 0.4rem;
}

.card-content p {
  font-size: 0.825rem;
  color: #64748b;
  margin: 0;
  line-height: 1.4;
}

.card-footer {
  margin-top: auto;
}

.card-btn {
  width: 100%;
}

.simple-wizard-container {
  display: flex;
  flex-direction: column;
  gap: 1rem;
}

.scene-header {
  display: flex;
  align-items: center;
  gap: 1rem;
}

.scene-title {
  font-size: 1.1rem;
  font-weight: 600;
  color: #0f172a;
}
</style>
