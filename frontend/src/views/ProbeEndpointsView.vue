<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { useRouter } from 'vue-router'
import { getAiEndpoints, type AiEndpoint } from '@/api/probe'

const router = useRouter()
const loading = ref(false)
const list = ref<AiEndpoint[]>([])
const total = ref(0)
const role = ref<'agent' | 'service' | ''>('')
const keyword = ref('')
const page = ref(1)
const pageSize = 20

const parseJa4 = (s: string) => { try { return JSON.parse(s || '[]') as string[] } catch { return [] } }

const load = async () => {
  loading.value = true
  try {
    const res = await getAiEndpoints({
      role: role.value || undefined, name: keyword.value || undefined,
      limit: pageSize, offset: (page.value - 1) * pageSize,
    })
    // 预处理：把 ja4_list 解析成行内字段，避免模板每次渲染都 JSON.parse
    list.value = res.endpoints.map(e => ({ ...e, _ja4_count: parseJa4(e.ja4_list).length }))
    total.value = res.total
  } finally { loading.value = false }
}

const onFilterChange = () => { page.value = 1; load() }

const categoryTag = (cat: string | null) => {
  const map: Record<string, string> = {
    AI_Coding: 'warning', LLM_API: 'primary', LLM_Web: 'success',
    LLM_Local: 'info', LLM_Gateway: 'danger', AI_Protocol: 'warning',
  }
  return cat ? (map[cat] || 'info') : 'info'
}

const lifecycleTag = (s: string) => {
  return s === 'active' ? 'success' : s === 'dormant' ? 'warning' : 'info'
}

const goDetail = (ip: string) => router.push(`/probe/endpoint/${ip}`)

onMounted(load)
</script>

<template>
  <div>
    <el-card class="mb-12" shadow="never">
      <el-form inline>
        <el-form-item label="角色">
          <el-select v-model="role" placeholder="全部" clearable style="width: 140px" @change="onFilterChange">
            <el-option label="客户端 (agent)" value="agent" />
            <el-option label="服务端 (service)" value="service" />
          </el-select>
        </el-form-item>
        <el-form-item label="名称">
          <el-input v-model="keyword" placeholder="如 Claude Code" clearable style="width: 200px" @keyup.enter="onFilterChange" @clear="onFilterChange" />
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="onFilterChange">查询</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <div style="overflow-x: auto;">
      <el-table :data="list" v-loading="loading" stripe @row-click="(r: AiEndpoint) => goDetail(r.ip)" style="cursor: pointer; min-width: 960px;">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="role" label="角色" width="80">
          <template #default="{ row }">
            <el-tag :type="row.role === 'agent' ? 'primary' : 'success'" size="small">{{ row.role === 'agent' ? '客户端' : '服务端' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="name" label="名称" min-width="140" show-overflow-tooltip />
        <el-table-column prop="vendor" label="厂商" width="110" />
        <el-table-column prop="category" label="类型" width="110">
          <template #default="{ row }">
            <el-tag :type="categoryTag(row.category)" size="small">{{ row.category || '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="JA4 指纹" width="160">
          <template #default="{ row }">
            <span class="mono" style="font-size: 12px;">{{ row._ja4_count ?? 0 }} 个</span>
          </template>
        </el-table-column>
        <el-table-column prop="flow_count" label="流次数" width="90" align="right" sortable />
        <el-table-column prop="lifecycle_state" label="生命周期" width="100">
          <template #default="{ row }">
            <el-tag :type="lifecycleTag(row.lifecycle_state)" size="small">{{ row.lifecycle_state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column prop="last_seen" label="最近活动" width="160" />
        <el-table-column label="扫描融合" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.scan_seen" type="warning" size="small">已融合 {{ row.fused_confidence ?? '-' }}</el-tag>
            <span v-else style="color: #c0c4cc; font-size: 12px;">未扫描</span>
          </template>
        </el-table-column>
      </el-table>
      </div>
      <div style="margin-top: 12px; display: flex; justify-content: space-between; align-items: center;">
        <span style="color: #909399; font-size: 13px;">共 {{ total }} 个端点，点击行查看端点画像</span>
        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
          layout="prev, pager, next, total" background @current-change="load" />
      </div>
    </el-card>
  </div>
</template>
