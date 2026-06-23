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
    <el-aside width="216px" class="nhi-sidebar">
      <div class="nhi-logo">
        <div class="nhi-logo-icon">N</div>
        <span class="nhi-logo-text">NHI 资产发现</span>
      </div>
      <el-menu :default-active="route.path" router background-color="transparent" text-color="#9ca3af" active-text-color="#4096ff">
        <el-menu-item v-for="r in $router.options.routes.filter(r => r.meta && !r.meta.hidden)" :key="r.path" :index="r.path">
          <el-icon><component :is="(r.meta as any).icon" /></el-icon>
          <span>{{ (r.meta as any).title }}</span>
        </el-menu-item>
      </el-menu>
    </el-aside>

    <el-container>
      <el-header class="nhi-header">
        <span class="nhi-page-title">{{ (route.meta as any)?.title || 'NHI' }}</span>
        <div v-if="health" class="nhi-health-bar">
          <el-tag :type="health.probe_consumer === 'running' ? 'success' : 'danger'" size="small">
            Probe {{ health.probe_consumer }}
          </el-tag>
          <el-tag :type="health.scan_scheduler === 'running' ? 'success' : 'info'" size="small">
            Scan {{ health.scan_scheduler }}
          </el-tag>
          <span class="nhi-health-sep">|</span>
          <span>DB {{ fmtSize(health.db_size_bytes) }}</span>
          <span>flows {{ health.tables?.flows ?? '-' }}</span>
        </div>
      </el-header>

      <el-main class="nhi-main">
        <router-view />
      </el-main>
    </el-container>
  </el-container>
</template>
