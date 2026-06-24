<script setup lang="ts">
import { ref, onMounted, reactive } from 'vue'
import { ElMessage, ElMessageBox } from 'element-plus'
import {
  triggerScan, listScanTargets, createScanTarget, updateScanTarget, deleteScanTarget,
  listScanTasks, getScanFindings, listScanServices, listScanCves,
  type ScanTarget, type ScanTask, type ScanFinding, type AiService, type CveRecord,
} from '@/api/scan'

const activeTab = ref('trigger')

// ── 立即扫描表单 ──
const triggerForm = reactive({
  scan_range: '', speed: 'normal', scan_strategy: 'ai_ports_only',
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
  name: '', cidr: '', scan_strategy: 'ai_ports_only', schedule_interval: 0, speed: 'normal', enabled: 0,
})

const loadTargets = async () => { try { targets.value = (await listScanTargets()).targets } catch {} }
const openCreate = () => {
  editing.value = null
  Object.assign(targetForm, { name: '', cidr: '', scan_strategy: 'ai_ports_only', schedule_interval: 0, speed: 'normal', enabled: 0 })
  targetDialog.value = true
}
const openEdit = (t: ScanTarget) => {
  editing.value = t
  Object.assign(targetForm, {
    name: t.name, cidr: t.cidr, scan_strategy: t.scan_strategy,
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
  const prev = t.enabled ? 0 : 1  // el-switch already flipped it, so prev is opposite
  try {
    await updateScanTarget(t.id, { enabled: t.enabled })
    ElMessage.success(`${t.name} ${t.enabled ? '已启用' : '已停用'}`)
  } catch {
    t.enabled = prev  // rollback on failure
  }
}

// ── 任务列表 ──
const tasks = ref<ScanTask[]>([])
const taskPage = ref(1)
const taskTotal = ref(0)
const loadTasks = async () => { try { const r = await listScanTasks(100, (taskPage.value - 1) * 100); tasks.value = r.tasks; taskTotal.value = r.total ?? r.tasks.length } catch {} }
const statusTag = (s: string) => s === 'done' ? 'success' : s === 'failed' ? 'danger' : s === 'running' ? 'warning' : 'info'

// ── 发现明细 ──
const findings = ref<ScanFinding[]>([])
const findingsTaskId = ref<string>('')
const findingsPage = ref(1)
const findingsTotal = ref(0)
const findingsLoading = ref(false)
const loadFindings = async () => {
  const taskId = findingsTaskId.value ? Number(findingsTaskId.value) : undefined
  findingsLoading.value = true
  try {
    const r = await getScanFindings({ task_id: taskId, limit: 50, offset: (findingsPage.value - 1) * 50 })
    findings.value = r.findings; findingsTotal.value = r.total
  } finally { findingsLoading.value = false }
}

// ── 服务资产 ──
const services = ref<AiService[]>([])
const svcPage = ref(1)
const svcTotal = ref(0)
const loadServices = async () => { try { const r = await listScanServices({ limit: 50, offset: (svcPage.value - 1) * 50 }); services.value = r.services; svcTotal.value = r.total } catch {} }
const riskTag = (r: string | null) => r === 'high' ? 'danger' : r === 'medium' ? 'warning' : r === 'low' ? 'success' : 'info'

// ── CVE ──
const cves = ref<CveRecord[]>([])
const cvePage = ref(1)
const cveTotal = ref(0)
const loadCves = async () => { try { const r = await listScanCves({ limit: 50, offset: (cvePage.value - 1) * 50 }); cves.value = r.cves; cveTotal.value = r.total } catch {} }
const cveTag = (s: string) => s === 'critical' ? 'danger' : s === 'high' ? 'danger' : s === 'medium' ? 'warning' : 'info'

onMounted(() => { loadTargets(); loadTasks(); loadServices(); loadCves() })
</script>

<template>
  <el-tabs v-model="activeTab" type="border-card">
    <!-- 立即扫描 -->
    <el-tab-pane label="立即扫描" name="trigger">
      <el-card shadow="never" style="max-width: 640px;">
        <el-form :model="triggerForm" label-width="100px">
          <el-form-item label="扫描范围">
            <el-input v-model="triggerForm.scan_range" placeholder="支持 IP / IP1-IP2 / CIDR，如 192.168.1.111 或 192.168.1.10-20 或 192.168.1.0/24" />
          </el-form-item>
          <el-form-item label="扫描速率">
            <el-radio-group v-model="triggerForm.speed">
              <el-radio-button value="slow">慢速 (100pps)</el-radio-button>
              <el-radio-button value="normal">正常 (500pps)</el-radio-button>
              <el-radio-button value="fast">快速 (2000pps)</el-radio-button>
            </el-radio-group>
          </el-form-item>
          <el-form-item label="扫描策略">
            <el-select v-model="triggerForm.scan_strategy" style="width: 220px">
              <el-option label="仅 AI 端口 (ai_ports_only)" value="ai_ports_only" />
              <el-option label="仅 Web 端口 (web_only)" value="web_only" />
              <el-option label="全部端口 (full)" value="full" />
            </el-select>
          </el-form-item>
          <el-form-item>
            <el-button type="primary" :loading="triggering" @click="doTrigger">立即扫描</el-button>
            <el-alert type="info" :closable="false" style="margin-top: 8px;">
              慢速适用于生产网/脆弱服务；快速适用于内网测试。扫描会产生网络流量，请确保已授权。
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
              <el-option label="仅 AI 端口" value="ai_ports_only" />
              <el-option label="仅 Web 端口" value="web_only" />
              <el-option label="全部端口" value="full" />
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

    <!-- 任务列表 -->
    <el-tab-pane label="扫描任务" name="tasks">
      <el-button class="mb-12" @click="loadTasks">刷新</el-button>
      <div style="overflow-x: auto;">
      <el-table :data="tasks" stripe size="small" style="min-width: 920px;">
        <el-table-column prop="id" label="ID" width="60" />
        <el-table-column prop="task_type" label="类型" width="90" />
        <el-table-column prop="status" label="状态" width="90">
          <template #default="{ row }"><el-tag :type="statusTag(row.status)" size="small">{{ row.status }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="ports_scanned" label="端口数" width="80" align="right" />
        <el-table-column prop="findings_count" label="发现数" width="80" align="right" />
        <el-table-column prop="started_at" label="开始" width="160" />
        <el-table-column prop="finished_at" label="结束" width="160" />
        <el-table-column prop="error_msg" label="错误" show-overflow-tooltip />
      </el-table>
      </div>
      <el-pagination v-if="taskTotal > 0" v-model:current-page="taskPage" :page-size="100" :total="taskTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadTasks" />
    </el-tab-pane>

    <!-- 发现明细 -->
    <el-tab-pane label="扫描发现" name="findings">
      <div class="mb-12">
        <el-input v-model="findingsTaskId" placeholder="task_id 过滤" style="width: 140px" />
        <el-button @click="() => { findingsPage = 1; loadFindings() }">查询</el-button>
      </div>
      <div style="overflow-x: auto;">
      <el-table :data="findings" stripe size="small" max-height="560" v-loading="findingsLoading" style="min-width: 1020px;">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="state" label="状态" width="70" />
        <el-table-column prop="service_raw" label="nmap服务" width="100" show-overflow-tooltip />
        <el-table-column prop="api_path" label="API路径" width="110" show-overflow-tooltip />
        <el-table-column prop="api_status" label="HTTP" width="70" />
        <el-table-column prop="ai_vendor" label="AI厂商" width="100" />
        <el-table-column prop="ai_service" label="AI服务" min-width="120" show-overflow-tooltip />
        <el-table-column prop="confidence" label="置信度" width="80" align="right" />
        <el-table-column prop="found_at" label="发现时间" width="160" />
      </el-table>
      </div>
      <el-pagination v-if="findingsTotal > 0" v-model:current-page="findingsPage" :page-size="50" :total="findingsTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadFindings" />
    </el-tab-pane>

    <!-- 服务资产 -->
    <el-tab-pane label="AI服务资产" name="services">
      <el-button class="mb-12" @click="loadServices">刷新</el-button>
      <div style="overflow-x: auto;">
      <el-table :data="services" stripe size="small" max-height="560" style="min-width: 920px;">
        <el-table-column prop="ip" label="IP" width="140" />
        <el-table-column prop="port" label="端口" width="70" />
        <el-table-column prop="service" label="服务" min-width="120" />
        <el-table-column prop="vendor" label="厂商" width="100" />
        <el-table-column prop="version" label="版本" width="90" />
        <el-table-column prop="scan_count" label="扫描次数" width="90" align="right" />
        <el-table-column label="Probe融合" width="100">
          <template #default="{ row }">
            <el-tag v-if="row.probe_seen" type="warning" size="small">{{ row.fused_confidence != null ? Number(row.fused_confidence).toFixed(2) : '-' }}</el-tag>
            <span v-else style="color:#c0c4cc">未融合</span>
          </template>
        </el-table-column>
        <el-table-column label="风险" width="80">
          <template #default="{ row }"><el-tag :type="riskTag(row.risk_level)" size="small">{{ row.risk_level || '-' }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="cve_count" label="CVE数" width="70" align="right" />
      </el-table>
      </div>
      <el-pagination v-if="svcTotal > 0" v-model:current-page="svcPage" :page-size="50" :total="svcTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadServices" />
    </el-tab-pane>

    <!-- CVE -->
    <el-tab-pane label="CVE漏洞" name="cve">
      <el-button class="mb-12" @click="loadCves">刷新</el-button>
      <div style="overflow-x: auto;">
      <el-table :data="cves" stripe size="small" style="min-width: 780px;">
        <el-table-column prop="cve_id" label="CVE ID" width="180" class-name="mono" />
        <el-table-column prop="service" label="服务" width="120" />
        <el-table-column prop="affected_version" label="影响版本" width="120" />
        <el-table-column prop="severity" label="严重度" width="90">
          <template #default="{ row }"><el-tag :type="cveTag(row.severity)" size="small">{{ row.severity }}</el-tag></template>
        </el-table-column>
        <el-table-column prop="cvss_score" label="CVSS" width="70" align="right" />
        <el-table-column prop="description" label="描述" show-overflow-tooltip />
      </el-table>
      </div>
      <el-pagination v-if="cveTotal > 0" v-model:current-page="cvePage" :page-size="50" :total="cveTotal"
        layout="prev, pager, next, total" background class="mt-12" @current-change="loadCves" />
    </el-tab-pane>
  </el-tabs>
</template>
