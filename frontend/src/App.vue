<script setup lang="ts">
import { ref, onMounted, onUnmounted } from 'vue'
import { useRoute } from 'vue-router'
import { getHealth, type HealthResp } from '@/api/probe'

const route = useRoute()
const health = ref<HealthResp | null>(null)
let timer: number | null = null

const loadHealth = async () => {
  try { health.value = await getHealth() } catch {}
}

const fmtSize = (b: number) => {
  if (b > 1e9) return (b / 1e9).toFixed(1) + ' GB'
  if (b > 1e6) return (b / 1e6).toFixed(1) + ' MB'
  if (b > 1e3) return (b / 1e3).toFixed(1) + ' KB'
  return b + ' B'
}

onMounted(() => { loadHealth(); timer = window.setInterval(loadHealth, 10000) })
onUnmounted(() => { if (timer) clearInterval(timer) })
</script>

<template>
  <el-container style="height: 100%">
    <el-aside width="220px" style="background: #304156">
      <div style="height: 60px; display: flex; align-items: center; justify-content: center; color: #fff; font-size: 16px; font-weight: 700;">
        NHI 资产发现
      </div>
      <el-menu :default-active="route.path" router background-color="#304156" text-color="#bfcbd9" active-text-color="#409eff">
        <el-menu-item v-for="r in $router.options.routes.filter(r => r.meta && !r.meta.hidden)" :key="r.path" :index="r.path">
          <el-icon><component :is="(r.meta as any).icon" /></el-icon>
          <span>{{ (r.meta as any).title }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>
    <el-container>
      <el-header style="background: #fff; border-bottom: 1px solid #e6e6e6; display: flex; align-items: center; justify-content: space-between; height: 56px;">
        <span style="font-size: 16px; font-weight: 600;">{{ (route.meta as any)?.title || 'NHI' }}</span>
        <div v-if="health" style="font-size: 12px; color: #909399; display: flex; gap: 16px; align-items: center;">
          <el-tag :type="health.probe_consumer === 'running' ? 'success' : 'danger'" size="small">Probe {{ health.probe_consumer }}</el-tag>
          <el-tag :type="health.scan_scheduler === 'running' ? 'success' : 'info'" size="small">Scan {{ health.scan_scheduler }}</el-tag>
          <span>DB {{ fmtSize(health.db_size_bytes) }}</span>
          <span>flows {{ health.tables?.flows ?? '-' }}</span>
        </div>
      </el-header>
      <el-main style="padding: 16px; overflow-y: auto;">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>
