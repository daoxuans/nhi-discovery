<script setup lang="ts">
import { ref, onMounted, onUnmounted, reactive } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  triggerScan, listScanTargets, createScanTarget, updateScanTarget, deleteScanTarget,
  listScanTasks, getScanFindings,
  type ScanTarget, type ScanTask, type ScanFinding,
} from '@/api/scan'

// ── 立即扫描表单 ──
const triggerForm = reactive({
  scan_range: '', speed: 'normal', scan_strategy: 'deep',
})
const triggering = ref(false)

const doTrigger = async () => {
  if (!triggerForm.scan_range.trim()) { ElMessage.warning('请输入扫描范围'); return }
  triggering.value = true
  try {
    const res = await triggerScan({
      scan_range: triggerForm.scan_range, speed: triggerForm.speed, scan_strategy: triggerForm.scan_strategy,
    })
    ElMessage.success(`扫描已触发，task_id=${res.task_id}`)
    activeTab.value = 'tasks'
    loadTasks()
  } finally { triggering.value = false }
}

// ── 扫描目标 CRUD ──
const targets = ref<ScanTarget[]>([])
const targetDialog = ref(false)
const editing = ref<ScanTarget | null>(null)
const saving = ref(false)
const targetForm = reactive({
  name: '', cidr: '', scan_strategy: 'deep', schedule_interval: 0, speed: 'normal', enabled: 0,
})

const loadTargets = async () => { try { targets.value = (await listScanTargets()).targets } catch {} }
const openCreate = () => {
  editing.value = null
  Object.assign(targetForm, { name: '', cidr: '', scan_strategy: 'deep', schedule_interval: 0, speed: 'normal', enabled: 0 })
  targetDialog.value = true
}
const openEdit = (t: ScanTarget) => {
  editing.value = t
  Object.assign(targetForm, {
    name: t.name, cidr: t.cidr, scan_strategy: t.scan_strategy || 'deep',
    schedule_interval: t.schedule_interval ?? t.full_interval,
    speed: t.speed ?? 'normal', enabled: t.enabled,
  })
  targetDialog.value = true
}
const saveTarget = async () => {
  const body = { name: targetForm.name, cidr: targetForm.cidr, scan_strategy: targetForm.scan_strategy,
    schedule_interval: targetForm.schedule_interval, speed: targetForm.speed, enabled: targetForm.enabled }
  saving.value = true
  try {
    if (editing.value) {
      await updateScanTarget(editing.value.id, body); ElMessage.success('已更新')
    } else {
      await createScanTarget(body); ElMessage.success('已创建')
    }
    targetDialog.value = false; loadTargets()
  } catch {
  } finally {
    saving.value = false
  }
}
const removeTarget = async (t: ScanTarget) => {
  try {
    await ElMessageBox.confirm(`删除扫描目标 ${t.name}？`, '确认', { type: 'warning' })
  } catch { return }
  try {
    await deleteScanTarget(t.id)
    ElMessage.success('已删除')
    loadTargets()
  } catch {}
}
const toggleEnabled = async (t: ScanTarget) => {
  const prev = t.enabled ? 0 : 1
  try {
    await updateScanTarget(t.id, { enabled: t.enabled })
    ElMessage.success(`${t.name} ${t.enabled ? '已启用' : '已停用'}`)
  } catch {
    t.enabled = prev
  }
}

// ── 任务列表 ──
const tasks = ref<ScanTask[]>([])
const taskLoading = ref(false)
const taskPage = ref(1)
const taskPageSize = 15
const taskTotal = ref(0)
const taskTypeFilter = ref('')
let taskTimer: number | null = null

const loadTasks = async () => {
  taskLoading.value = true
  try {
    const r = await listScanTasks(100, (taskPage.value - 1) * 100)
    let filtered = r.tasks
    if (taskTypeFilter.value) {
      filtered = filtered.filter(t => t.task_type === taskTypeFilter.value)
    }
    tasks.value = filtered
    taskTotal.value = r.total ?? r.tasks.length
  } finally { taskLoading.value = false }
}

// 如果有 running 任务，每 2s 自动刷新进度
const startTaskPolling = () => {
  if (taskTimer) return
  taskTimer = window.setInterval(async () => {
    const hasRunning = tasks.value.some(t => t.status === 'running')
    if (!hasRunning) {
      stopTaskPolling()
      return
    }
    await loadTasks()
  }, 5000)
}
const stopTaskPolling = () => {
  if (taskTimer) { clearInterval(taskTimer); taskTimer = null }
}

const onTaskFilterChange = () => { taskPage.value = 1; loadTasks() }
const statusTag = (s: string) => s === 'done' ? 'success' : s === 'failed' ? 'danger' : s === 'running' ? 'warning' : 'info'

const progressPhaseName = (p: string | null) => {
  if (p === 'port_scan') return '端口扫描'
  if (p === 'content_probe') return '内容探测'
  return p || ''
}

const progressPercent = (done: number, total: number) => {
  if (!total) return 0
  return Math.round((done / total) * 100)
}

const activeTab = ref('trigger')

// ── 任务详情弹窗 ──
const detailVisible = ref(false)
const detailTaskId = ref<number | null>(null)
const detailTaskLabel = ref('')
const findings = ref<ScanFinding[]>([])
const findingsLoading = ref(false)
const findingsTotal = ref(0)
const findingsPage = ref(1)

const openTaskDetail = async (task: ScanTask) => {
  detailTaskId.value = task.id
  detailTaskLabel.value = `任务 #${task.id} (${task.task_type}, ${task.status})`
  findingsPage.value = 1
  detailVisible.value = true
  await loadFindings()
}

const loadFindings = async () => {
  if (!detailTaskId.value) return
  findingsLoading.value = true
  try {
    const r = await getScanFindings({ task_id: detailTaskId.value, limit: 50, offset: (findingsPage.value - 1) * 50 })
    findings.value = r.findings; findingsTotal.value = r.total
  } catch {} finally { findingsLoading.value = false }
}

onMounted(() => { loadTargets(); loadTasks(); startTaskPolling() })
onUnmounted(() => { stopTaskPolling() })
</script>

<template>
  <el-tabs v-model="activeTab" type="border-card">
    <!-- 立即扫描 -->
    <el-tab-pane label="立即扫描" name="trigger">
      <el-card shadow="never" style="max-width: 680px;">
        <el-form :model="triggerForm" label-width="100px">
          <el-form-item label="扫描范围">
            <el-input v-model="triggerForm.scan_range" placeholder="IP / IP1-IP2 / CIDR，如 192.168.1.115 或 192.168.1.0/24" />
          </el-form-item>
          <el-form-item label="扫描速率">
            <el-radio-group v-model="triggerForm.speed">
              <el-radio-button value="slow">慢速</el-radio-button>
              <el-radio-button value="normal">正常</el-radio-button>
              <el-radio-button value="fast">快速</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="扫描策略">
            <el-select v-model="triggerForm.scan_strategy" style="width: 220px">
              <el-option label="深度指纹 (推荐, 全端口+内容指纹)" value="deep" />
              <el-option label="快速探测 (10个AI默认端口)" value="quick" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="triggering" @click="doTrigger">立即扫描</el-button>
            <el-alert type="info" :closable="false" style="margin-top: 8px;">
              深度指纹扫描全端口 1-65535 + 内容指纹，可发现自定义端口 AI agent；快速探测只扫 10 个默认 AI 端口，秒级完成
            </el-alert>
          </el-form-item>
        </el-form>
      </el-card>
    </el-tab-pane>

    <!-- 定时目标 -->
    <el-tab-pane label="定时扫描目标" name="targets">
      <div class="mb-12">
        <el-button type="primary" @click="openCreate">新建目标</el-button>
        <el-button @click="loadTargets">刷新</el-button>
      </div>
      <div style="overflow-x: auto;">
      <el-table :data="targets" stripe style="min-width: 960px;">
        <el-table-column prop="name" label="名称" width="120" />
        <el-table-column prop="cidr" label="扫描范围" min-width="180" show-overflow-tooltip />
        <el-table-column prop="scan_strategy" label="策略" width="130" />
        <el-table-column label="定时间隔" width="110">
          <template #default="{ row }">{{ row.schedule_interval ?? row.full_interval }}s</template>
        </el-table-column>
        <el-table-column label="速率" width="90">
          <template #default="{ row }"><el-tag size="small">{{ row.speed ?? 'normal' }}</el-tag></template>
        </el-table-column>
        <el-table-column label="启用" width="80">
          <template #default="{ row }">
            <el-switch v-model="row.enabled" :active-value="1" :inactive-value="0" @change="toggleEnabled(row)" />
          </template>
        </el-table-column>
        <el-table-column label="操作" width="140">
          <template #default="{ row }">
            <el-button size="small" link @click="openEdit(row)">编辑</el-button>
            <el-button size="small" link type="danger" @click="removeTarget(row)">删除</el-button>
          </template>
        </el-table-column>
      </el-table>
      </div>

      <el-dialog v-model="targetDialog" :title="editing ? '编辑扫描目标' : '新建扫描目标'" width="520px">
        <el-form :model="targetForm" label-width="100px">
          <el-form-item label="名称"><el-input v-model="targetForm.name" /></el-form-item>
          <el-form-item label="扫描范围"><el-input v-model="targetForm.cidr" placeholder="IP / IP1-IP2 / CIDR" /></el-form-item>
          <el-form-item label="扫描策略">
            <el-select v-model="targetForm.scan_strategy" style="width: 100%">
              <el-option label="深度指纹 (推荐)" value="deep" />
              <el-option label="快速探测" value="quick" />
            </el-select>
          </el-form-item>
          <el-form-item label="定时间隔(秒)"><el-input-number v-model="targetForm.schedule_interval" :min="0" :step="60" /></el-form-item>
          <el-form-item label="速率">
            <el-radio-group v-model="targetForm.speed">
              <el-radio-button value="slow">慢速</el-radio-button>
              <el-radio-button value="normal">正常</el-radio-button>
              <el-radio-button value="fast">快速</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="启用"><el-switch v-model="targetForm.enabled" :active-value="1" :inactive-value="0" /></el-form-item>
        </el-form>
        <template #footer>
          <el-button @click="targetDialog = false">取消</el-button>
          <el-button type="primary" :loading="saving" @click="saveTarget">保存</el-button>
        </template>
      </el-dialog>
    </el-tab-pane>

    <!-- 扫描任务列表 -->
    <el-tab-pane label="扫描任务" name="tasks">
      <el-form inline class="mb-12">
        <el-form-item label="任务类型">
          <el-select v-model="taskTypeFilter" placeholder="全部" clearable style="width: 140px" @change="onTaskFilterChange">
            <el-option label="手动" value="manual" />
            <el-option label="定时全量" value="full" />
          </el-select>
        </el-form-item>
        <el-form-item>
          <el-button type="primary" @click="loadTasks">查询</el-button>
        </el-form-item>
      </el-form>
      <div style="overflow-x: auto;">
      <el-table :data="tasks" v-loading="taskLoading" stripe size="small" style="min-width: 980px;">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="task_type" label="类型" width="90" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }"><el-tag :type="statusTag(row.status)" size="small">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column label="进度" width="200">
          <template #default="{ row }">
            <div v-if="row.status === 'running' && row.progress_total" style="display: flex; align-items: center; gap: 6px;">
              <span style="font-size: 11px; color: #909399; white-space: nowrap;">{{ progressPhaseName(row.progress_phase) }}</span>
              <el-progress :percentage="progressPercent(row.progress_done, row.progress_total)"
                :stroke-width="8" :show-text="true" style="flex: 1; min-width: 60px;">
                <template #default="{ percentage }">
                  <span style="font-size: 11px;">{{ row.progress_done }}/{{ row.progress_total }}</span>
                </template>
              </el-progress>
            </div>
            <span v-else-if="row.status === 'done'" style="color: #67c23a; font-size: 12px;">✓ 完成</span>
            <span v-else-if="row.status === 'failed'" style="color: #f56c6c; font-size: 12px;">✗ 失败</span>
            <span v-else style="color: #909399; font-size: 12px;">排队中</span>
          </template>
        </el-table-column>
        <el-table-column prop="ports_scanned" label="端口数" width="80" align="right" />
        <el-table-column prop="findings_count" label="发现数" width="80" align="right" />
        <el-table-column prop="started_at" label="开始" width="160" />
        <el-table-column prop="finished_at" label="结束" width="160" />
        <el-table-column label="操作" width="80">
          <template #default="{ row }">
            <el-button size="small" link type="primary" @click="openTaskDetail(row)">详情</el-button>
          </template>
        </el-table-column>
      </el-table>
      </div>
      <el-pagination v-if="taskTotal > taskPageSize" v-model:current-page="taskPage" :page-size="taskPageSize" :total="taskTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadTasks" />
    </el-tab-pane>

    <!-- 任务详情弹窗 -->
    <el-dialog v-model="detailVisible" :title="detailTaskLabel" width="1100px" top="4vh">
      <div style="overflow-x: auto;">
      <el-table :data="findings" stripe size="small" max-height="560" v-loading="findingsLoading" style="min-width: 1060px;">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="state" label="状态" width="70" />
        <el-table-column prop="service_raw" label="nmap 服务" width="100" show-overflow-tooltip />
        <el-table-column prop="api_path" label="API 路径" width="110" show-overflow-tooltip />
        <el-table-column prop="api_status" label="HTTP" width="70" />
        <el-table-column prop="ai_vendor" label="AI 厂商" width="100" />
        <el-table-column prop="ai_service" label="AI 服务" min-width="130" show-overflow-tooltip />
        <el-table-column label="置信度" width="80" align="right">
          <template #default="{ row }">
            <el-tag v-if="row.confidence != null" :type="row.confidence >= 0.8 ? 'success' : row.confidence >= 0.5 ? 'warning' : 'info'" size="small">
              {{ row.confidence.toFixed(2) }}
            </el-tag>
            <span v-else style="color:#c0c4cc">-</span>
          </template>
        </el-table-column>
        <el-table-column prop="found_at" label="发现时间" width="160" />
      </el-table>
      </div>
      <el-pagination v-if="findingsTotal > 0" v-model:current-page="findingsPage" :page-size="50" :total="findingsTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadFindings" />
    </el-dialog>
  </el-tabs>
</template>
