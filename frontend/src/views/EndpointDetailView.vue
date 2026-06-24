<script setup lang="ts">
import { ref, onMounted, watch } from 'vue'
import { useRoute, useRouter } from 'vue-router'
import { getAiEndpoint, type EndpointDetail } from '@/api/probe'

const route = useRoute()
const router = useRouter()
const loading = ref(false)
const error = ref(false)
const detail = ref<EndpointDetail | null>(null)
const ip = ref(route.params.ip as string)

const parseArr = (s: string) => { try { return JSON.parse(s || '[]') as string[] } catch { return [] } }

const load = async () => {
  loading.value = true
  error.value = false
  detail.value = null
  try {
    detail.value = await getAiEndpoint(ip.value)
  } catch (e) {
    console.error('[EndpointDetail] load error:', e)
    error.value = true
  } finally { loading.value = false }
}

watch(() => route.params.ip, (newIp) => {
  if (newIp) { ip.value = newIp as string; load() }
})

onMounted(load)
</script>

<template>
  <div v-loading="loading">
    <el-page-header @back="router.back()" style="margin-bottom: 16px;">
      <template #content>端点画像 — {{ ip }}</template>
    </el-page-header>

    <el-alert v-if="error" type="error" :closable="false" class="mb-16" title="加载失败">
      无法获取端点 {{ ip }} 的画像数据，请检查后端服务或稍后重试。
      <el-button link type="primary" @click="load">重试</el-button>
    </el-alert>

    <template v-if="detail">
      <el-row :gutter="12" class="mb-16">
        <el-col :span="8"><el-card shadow="hover"><div class="stat-value">{{ detail.agents?.length || 0 }}</div><div class="stat-label">运行的 AI 客户端</div></el-card></el-col>
        <el-col :span="8"><el-card shadow="hover"><div class="stat-value">{{ detail.services?.length || 0 }}</div><div class="stat-label">提供的 AI 服务</div></el-card></el-col>
        <el-col :span="8"><el-card shadow="hover"><div class="stat-value">{{ detail.scan_services?.length || 0 }}</div><div class="stat-label">扫描发现的服务</div></el-card></el-col>
      </el-row>

      <el-row :gutter="12">
        <el-col :span="12" class="mb-12">
          <el-card shadow="hover">
            <template #header>AI 客户端 (agent)</template>
            <el-table :data="detail.agents || []" size="small" max-height="400">
              <el-table-column prop="name" label="名称" min-width="120" />
              <el-table-column prop="vendor" label="厂商" width="100" />
              <el-table-column prop="category" label="类型" width="100" />
              <el-table-column label="JA4" width="80">
                <template #default="{ row }"><span class="mono">{{ parseArr(row.ja4_list).length }}</span></template>
              </el-table-column>
              <el-table-column prop="flow_count" label="流次数" width="80" align="right" />
              <el-table-column prop="last_seen" label="最近" width="150" />
            </el-table>
          </el-card>
        </el-col>
        <el-col :span="12" class="mb-12">
          <el-card shadow="hover">
            <template #header>AI 服务 (service)</template>
            <el-table :data="detail.services || []" size="small" max-height="400">
              <el-table-column prop="name" label="服务名" min-width="120" />
              <el-table-column prop="vendor" label="厂商" width="100" />
              <el-table-column prop="category" label="类型" width="100" />
              <el-table-column label="模型" width="80">
                <template #default="{ row }"><span class="mono">{{ parseArr(row.models).length }}</span></template>
              </el-table-column>
              <el-table-column prop="flow_count" label="流次数" width="80" align="right" />
              <el-table-column prop="last_seen" label="最近" width="150" />
            </el-table>
          </el-card>
        </el-col>
      </el-row>

      <el-card shadow="hover" class="mb-12" v-if="detail.scan_services?.length">
        <template #header>扫描发现的服务 (Scan 侧)</template>
        <el-table :data="detail.scan_services" size="small">
          <el-table-column prop="port" label="端口" width="80" />
          <el-table-column prop="service" label="服务" min-width="120" />
          <el-table-column prop="vendor" label="厂商" width="100" />
          <el-table-column prop="version" label="版本" width="100" />
          <el-table-column prop="scan_count" label="扫描次数" width="90" align="right" />
          <el-table-column prop="last_seen" label="最近扫描" width="160" />
        </el-table>
      </el-card>

      <el-card shadow="hover">
        <template #header>生命周期事件</template>
        <el-table :data="detail.timeline || []" size="small" max-height="300">
          <el-table-column prop="occurred_at" label="时间" width="160" />
          <el-table-column prop="event_type" label="事件" width="120">
            <template #default="{ row }">
              <el-tag size="small">{{ row.event_type }}</el-tag>
            </template>
          </el-table-column>
          <el-table-column prop="old_state" label="原状态" width="100" />
          <el-table-column prop="new_state" label="新状态" width="100" />
          <el-table-column prop="detail" label="详情" show-overflow-tooltip />
        </el-table>
      </el-card>
    </template>
  </div>
</template>
