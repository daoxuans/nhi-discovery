<script setup lang="ts">
import { ref, onMounted, onUnmounted, watch, nextTick } from 'vue'
import * as echarts from 'echarts'
import { getFusedAssets, type FusedAsset } from '@/api/fusion'

const loading = ref(false)
const list = ref<FusedAsset[]>([])
const total = ref(0)
const source = ref('all')
const page = ref(1)
const pageSize = 50
const scatterEl = ref<HTMLElement>()

const load = async () => {
  loading.value = true
  try {
    const res = await getFusedAssets({
      source: source.value === 'all' ? undefined : source.value,
      limit: pageSize, offset: (page.value - 1) * pageSize,
    })
    list.value = res.assets
    total.value = res.total
  } finally { loading.value = false }
}

const onSourceChange = () => { page.value = 1; load() }

const renderScatter = () => {
  if (!scatterEl.value) return
  const c = echarts.getInstanceByDom(scatterEl.value) || echarts.init(scatterEl.value)
  if (!list.value.length) { c.clear(); return }
  const data = list.value.map(a => [a.scan_count, a.probe_flow_count || 0, a.fused_confidence || 0, `${a.ip}:${a.port} ${a.service}`])
  c.setOption({
    tooltip: { formatter: (p: any) => `${p.data[3]}<br/>scan: ${p.data[0]}, probe: ${p.data[1]}, fused: ${p.data[2]}` },
    xAxis: { name: 'Scan 次数', type: 'value' },
    yAxis: { name: 'Probe 流次数', type: 'value' },
    series: [{ type: 'scatter', data, symbolSize: (d: number[]) => 8 + d[2] * 20, itemStyle: { color: '#409eff' } }],
  })
}

watch(list, () => nextTick(renderScatter))

const confidenceTag = (c: number | null) => {
  if (c === null) return 'info'
  if (c >= 0.9) return 'success'
  if (c >= 0.7) return 'primary'
  if (c >= 0.5) return 'warning'
  return 'danger'
}

const riskTag = (r: string | null) => r === 'high' ? 'danger' : r === 'medium' ? 'warning' : r === null ? 'info' : 'success'
const lifecycleTag = (s: string) => s === 'active' ? 'success' : s === 'dormant' ? 'warning' : 'info'

onMounted(load)
onUnmounted(() => {
  if (scatterEl.value) echarts.getInstanceByDom(scatterEl.value)?.dispose()
})
</script>

<template>
  <div>
    <el-card class="mb-12" shadow="never">
      <el-form inline>
        <el-form-item label="数据来源">
          <el-select v-model="source" style="width: 200px" @change="onSourceChange">
            <el-option label="全部 (all)" value="all" />
            <el-option label="双源一致 (both)" value="both" />
            <el-option label="仅 Scan (scan)" value="scan" />
            <el-option label="仅 Probe (probe)" value="probe" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="load" :loading="loading">查询</el-button>
        </el-form-item>
      </el-form>
    </el-card>

    <el-alert v-if="total === 0" type="info" :closable="false" class="mb-12">
      当前无融合资产。融合资产 = Scan 主动发现的 AI 服务 与 Probe 被动捕获的流量 通过 IP 关联。
      可在「主动扫描」页扫描网段后，再回到此页查看融合结果。
    </el-alert>

    <el-card v-if="list.length" shadow="hover" class="mb-12">
      <template #header>Scan × Probe 融合散点图</template>
      <div ref="scatterEl" class="chart-box" />
    </el-card>

    <el-card shadow="never">
      <el-table :data="list" stripe v-loading="loading" size="small">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="service" label="服务" min-width="120" show-overflow-tooltip />
        <el-table-column prop="vendor" label="厂商" width="100" />
        <el-table-column prop="version" label="版本" width="90" />
        <el-table-column label="融合置信度" width="110">
          <template #default="{ row }">
            <el-tag :type="confidenceTag(row.fused_confidence)" size="small">{{ row.fused_confidence ?? '-' }}</el-tag>
          </template>
        </el-table-column>
        <el-table-column label="Probe 流量" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.probe_seen" type="success" size="small">{{ row.probe_flow_count }} 次</el-tag>
            <span v-else style="color:#c0c4cc">无</span>
          </template>
        </el-table-column>
        <el-table-column prop="scan_count" label="Scan 次数" width="90" align="right" />
        <el-table-column label="生命周期" width="100">
          <template #default="{ row }"><el-tag :type="lifecycleTag(row.lifecycle_state)" size="small">{{ row.lifecycle_state }}</el-tag></template>
        </el-table-column>
        <el-table-column label="风险" width="80">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk_level)" size="small">{{ row.risk_level || '-' }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="cve_count" label="CVE" width="60" align="right" />
        <el-table-column prop="scan_last_seen" label="最近扫描" width="160" />
      </el-table>
      <div v-if="total > 0" style="margin-top: 12px; display: flex; justify-content: flex-end;">
        <el-pagination v-model:current-page="page" :page-size="pageSize" :total="total"
          layout="prev, pager, next, total" background @current-change="load" />
      </div>
    </el-card>
  </div>
</template>
