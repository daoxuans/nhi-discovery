<script setup lang="ts">
import { ref, onMounted } from 'vue'
import { listScanServices, type AiService } from '@/api/scan'

const loading = ref(false)
const list = ref<AiService[]>([])
const total = ref(0)
const vendor = ref('')
const svcType = ref('')
const ip = ref('')
const lifecycle = ref('')
const page = ref(1)
const pageSize = 20

const load = async () => {
  loading.value = true
  try {
    const r = await listScanServices({
      vendor: vendor.value || undefined,
      svc_type: svcType.value || undefined,
      ip: ip.value || undefined,
      lifecycle_state: lifecycle.value || undefined,
      limit: pageSize, offset: (page.value - 1) * pageSize,
    })
    list.value = r.services
    total.value = r.total
  } finally { loading.value = false }
}

const onFilterChange = () => { page.value = 1; load() }

const riskTag = (r: string | null) =>
  r === 'high' ? 'danger' : r === 'medium' ? 'warning' : r === 'low' ? 'success' : 'info'

const lifecycleTag = (s: string) =>
  s === 'active' ? 'success' : s === 'dormant' ? 'warning' : 'info'

const fmtConfidence = (c: number | null) => {
  if (c === null) return '-'
  if (c >= 0.9) return '高'
  if (c >= 0.7) return '中'
  return '低'
}

const svcTypeOptions = [
  { label: '全部', value: '' },
  { label: 'LLM 本地', value: 'LLM_Local' },
  { label: 'LLM 平台', value: 'AI_Platform' },
  { label: 'LLM 网关', value: 'LLM_Gateway' },
  { label: 'AI 编码', value: 'AI_Coding' },
  { label: 'LLM API', value: 'LLM_API' },
  { label: 'LLM Web', value: 'LLM_Web' },
]

onMounted(load)
</script>

<template>
  <div>
    <el-card class="mb-12" shadow="never">
      <el-form inline>
        <el-form-item label="服务类型">
          <el-select v-model="svcType" placeholder="全部" clearable style="width: 150px" @change="onFilterChange">
            <el-option v-for="o in svcTypeOptions" :key="o.value" :label="o.label" :value="o.value" />
          </el-select>
        </el-form-item>
        <el-form-item label="厂商">
          <el-input v-model="vendor" placeholder="如 OpenAI" clearable style="width: 160px" @keyup.enter="onFilterChange" @clear="onFilterChange" />
        </el-form-item>
        <el-form-item label="IP">
          <el-input v-model="ip" placeholder="如 192.168.1.115" clearable style="width: 160px" @keyup.enter="onFilterChange" @clear="onFilterChange" />
        </el-form-item>
        <el-form-item label="生命周期">
          <el-select v-model="lifecycle" placeholder="全部" clearable style="width: 120px" @change="onFilterChange">
            <el-option label="活跃" value="active" />
            <el-option label="休眠" value="dormant" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="onFilterChange">查询</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-card shadow="never">
      <el-table :data="list" v-loading="loading" stripe size="small">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="service" label="服务名称" min-width="140" show-overflow-tooltip />
        <el-table-column prop="vendor" label="厂商" width="110" />
        <el-table-column label="类型" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.svc_type" size="small" type="info">{{ row.svc_type }}</el-tag>
            <span v-else style="color:#c0c4cc">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="version" label="版本" width="90">
          <template #default="{ row }">{{ row.version || '-' }}</template>
        </el-table-column>
        <el-table-column prop="scan_count" label="扫描次数" width="90" align="right" />
        <el-table-column label="最近扫描" width="160">
          <template #default="{ row }">{{ row.last_seen || '-' }}</template>
        </el-table-column>
        <el-table-column label="生命周期" width="90">
          <template #default="{ row }">
            <el-tag :type="lifecycleTag(row.lifecycle_state)" size="small">{{ row.lifecycle_state }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="风险" width="80">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk_level)" size="small">{{ row.risk_level || '-' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="CVE" width="60" align="right">
          <template #default="{ row }">
            <el-tag v-if="row.cve_count > 0" type="danger" size="small">{{ row.cve_count }}</el-tag>
            <span v-else style="color:#c0c4cc">0</span>
          </template>
        </el-table-column>
        <el-table-column label="融合" width="110">
          <template #default="{ row }">
            <el-tag v-if="row.probe_seen" :type="row.fused_confidence != null && row.fused_confidence >= 0.8 ? 'success' : 'warning'" size="small">
              已融合 {{ row.fused_confidence != null ? Number(row.fused_confidence).toFixed(2) : '-' }}
            </el-tag>
            <span v-else style="color:#c0c4cc; font-size:12px">仅扫描</span>
          </template>
        </el-table-column>
      </el-table>
      <div style="margin-top: 12px; display: flex; justify-content: space-between; align-items: center;">
        <span style="color: #909399; font-size: 13px;">共 {{ total }} 个扫描发现的 AI 服务资产</span>
        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
          layout="prev, pager, next, total" background @current-change="load" />
      </div>
    </el-card>
  </div>
</template>
