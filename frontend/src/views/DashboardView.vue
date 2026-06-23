<script setup lang="ts">
import { ref, onMounted, onUnmounted, nextTick } from 'vue'
import * as echarts from 'echarts'
import { getAiStats, type AiStatsResp } from '@/api/probe'
import { getFlowStats, type FlowStats } from '@/api/fusion'

const stats = ref<AiStatsResp | null>(null)
const flowStats = ref<FlowStats | null>(null)
const timeRange = ref('24h')
let timer: number | null = null

const vendorEl = ref<HTMLElement>()
const agentEl = ref<HTMLElement>()
const svcTypeEl = ref<HTMLElement>()
const detectionEl = ref<HTMLElement>()

const load = async () => {
  try {
    stats.value = await getAiStats(timeRange.value)
    flowStats.value = await getFlowStats()
    await nextTick()
    renderCharts()
  } catch (e) {
    console.error('[Dashboard] load error:', e)
  }
}

const toBarData = (obj: Record<string, number> | undefined, top = 12) => {
  if (!obj) return { names: [] as string[], values: [] as number[] }
  const sorted = Object.entries(obj).sort((a, b) => b[1] - a[1]).slice(0, top)
  return { names: sorted.map(s => s[0]), values: sorted.map(s => s[1]) }
}

const renderCharts = () => {
  const s = stats.value
  const f = flowStats.value

  if (s && vendorEl.value) {
    const c = echarts.getInstanceByDom(vendorEl.value) || echarts.init(vendorEl.value)
    const d = toBarData(s.vendor_counts)
    c.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 110, right: 20, top: 10, bottom: 10 },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: [...d.names].reverse() },
      series: [{ type: 'bar', data: [...d.values].reverse(), itemStyle: { color: '#409eff' } }],
    })
  }

  if (s && agentEl.value) {
    const c = echarts.getInstanceByDom(agentEl.value) || echarts.init(agentEl.value)
    const d = toBarData(s.agent_counts)
    c.setOption({
      tooltip: { trigger: 'axis' },
      grid: { left: 130, right: 20, top: 10, bottom: 10 },
      xAxis: { type: 'value' },
      yAxis: { type: 'category', data: [...d.names].reverse() },
      series: [{ type: 'bar', data: [...d.values].reverse(), itemStyle: { color: '#67c23a' } }],
    })
  }

  if (s && svcTypeEl.value) {
    const c = echarts.getInstanceByDom(svcTypeEl.value) || echarts.init(svcTypeEl.value)
    const data = Object.entries(s.svc_type_counts || {}).map(([name, value]) => ({ name, value }))
    c.setOption({
      tooltip: { trigger: 'item' },
      legend: { bottom: 0, type: 'scroll' },
      series: [{ type: 'pie', radius: ['40%', '68%'], top: -20, data, label: { formatter: '{b}: {d}%' } }],
    })
  }

  if (f && detectionEl.value) {
    const c = echarts.getInstanceByDom(detectionEl.value) || echarts.init(detectionEl.value)
    const det = f.detection?.detected || 0
    const not = f.detection?.['not-detected'] || 0
    c.setOption({
      tooltip: { trigger: 'item' },
      legend: { bottom: 0 },
      series: [{ type: 'pie', radius: '65%', top: -20, data: [
        { name: '已分类', value: det, itemStyle: { color: '#409eff' } },
        { name: '待分类', value: not, itemStyle: { color: '#dcdfe6' } },
      ], label: { formatter: '{b}: {d}%' } }],
    })
  }
}

const onResize = () => {
  ;[vendorEl, agentEl, svcTypeEl, detectionEl].forEach(r => {
    if (r.value) echarts.getInstanceByDom(r.value)?.resize()
  })
}

onMounted(async () => {
  await load()
  timer = window.setInterval(load, 30000)
  window.addEventListener('resize', onResize)
})

onUnmounted(() => {
  if (timer) clearInterval(timer)
  window.removeEventListener('resize', onResize)
  ;[vendorEl, agentEl, svcTypeEl, detectionEl].forEach(r => {
    if (r.value) echarts.getInstanceByDom(r.value)?.dispose()
  })
})
</script>

<template>
  <div>
    <!-- 概览卡片 -->
    <el-row :gutter="16" class="mb-16">
      <el-col :span="6">
        <el-card shadow="never" class="stat-card"><div class="stat-value">{{ stats?.confirmed ?? '-' }}</div><div class="stat-label">AI 事件数</div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card"><div class="stat-value">{{ stats?.percentage != null ? stats.percentage.toFixed(1) : '-' }}%</div><div class="stat-label">AI 流量占比</div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card"><div class="stat-value">{{ flowStats?.total ?? '-' }}</div><div class="stat-label">总流量数</div></el-card>
      </el-col>
      <el-col :span="6">
        <el-card shadow="never" class="stat-card"><div class="stat-value">{{ Object.keys(stats?.agent_counts || {}).length }}</div><div class="stat-label">识别 Agent 种类</div></el-card>
      </el-col>
    </el-row>

    <el-card class="mb-16" shadow="never">
      <div class="card-header">
        <span>AI 资产统计</span>
        <el-radio-group v-model="timeRange" size="small" @change="load">
          <el-radio-button value="1h">近1小时</el-radio-button>
          <el-radio-button value="24h">近24小时</el-radio-button>
          <el-radio-button value="7d">近7天</el-radio-button>
          <el-radio-button value="all">全部</el-radio-button>
        </el-radio-group>
      </div>
    </el-card>

    <!-- 图表区 -->
    <el-row :gutter="12">
      <el-col :span="12" class="mb-12">
        <el-card shadow="hover">
          <template #header>AI 服务厂商分布 (Top12)</template>
          <div ref="vendorEl" class="chart-box" />
        </el-card>
      </el-col>
      <el-col :span="12" class="mb-12">
        <el-card shadow="hover">
          <template #header>AI Agent 客户端分布 (Top12)</template>
          <div ref="agentEl" class="chart-box" />
        </el-card>
      </el-col>
      <el-col :span="12" class="mb-12">
        <el-card shadow="hover">
          <template #header>AI 服务类型分布</template>
          <div ref="svcTypeEl" class="chart-box" />
        </el-card>
      </el-col>
      <el-col :span="12" class="mb-12">
        <el-card shadow="hover">
          <template #header>流量识别率</template>
          <div ref="detectionEl" class="chart-box" />
        </el-card>
      </el-col>
    </el-row>

    <!-- Top hostname / JA4 -->
    <el-row :gutter="12">
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>Top AI 域名 (confirmed)</template>
          <el-table :data="stats?.top_hostnames || []" size="small" max-height="320">
            <el-table-column type="index" width="50" />
            <el-table-column prop="hostname" label="域名" show-overflow-tooltip />
            <el-table-column prop="count" label="事件数" width="100" align="right" />
          </el-table>
        </el-card>
      </el-col>
      <el-col :span="12">
        <el-card shadow="hover">
          <template #header>Top JA4 指纹</template>
          <el-table :data="stats?.top_ja4 || []" size="small" max-height="320">
            <el-table-column type="index" width="50" />
            <el-table-column prop="ja4" label="JA4 指纹" show-overflow-tooltip class-name="mono" />
            <el-table-column prop="count" label="出现次数" width="100" align="right" />
          </el-table>
        </el-card>
      </el-col>
    </el-row>
  </div>
</template>
