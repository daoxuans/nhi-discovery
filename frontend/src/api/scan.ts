import http from './http'

export interface ScanTarget {
  id: number
  name: string
  cidr: string
  scan_strategy: string
  full_interval: number
  incr_interval: number
  rate_limit_pps: number
  per_target_qps: number
  scan_window: string
  enabled: number
  // 新字段（后端待实现，前端先兼容）
  schedule_interval?: number
  speed?: string
  created_at: string
}

export interface ScanTask {
  id: number
  task_uuid: string
  target_id: number | null
  task_type: string
  status: string
  started_at: string | null
  finished_at: string | null
  targets_scanned: number
  ports_scanned: number
  findings_count: number
  progress_total: number
  progress_done: number
  progress_phase: string | null
  error_msg: string | null
  created_at: string
}

export interface ScanFinding {
  id: number
  task_id: number
  ip: string
  port: number
  state: string
  service_raw: string | null
  api_path: string | null
  api_status: number | null
  models_detected: string | null
  version_detected: string | null
  ai_vendor: string | null
  ai_service: string | null
  ai_svc_type: string | null
  confidence: number | null
  found_at: string
}

export interface AiService {
  id: number
  ip: string
  port: number
  service: string
  vendor: string | null
  svc_type: string | null
  version: string | null
  models: string | null
  lifecycle_state: string
  scan_count: number
  probe_seen: number
  fused_confidence: number | null
  risk_level: string | null
  cve_count: number
  last_seen: string
}

export interface CveRecord {
  id: number
  cve_id: string
  service: string
  vendor: string | null
  affected_version: string
  severity: string
  cvss_score: number | null
  description: string | null
}

// ── 立即扫描 ──
export const triggerScan = (body: {
  scan_range?: string; cidr?: string; speed?: string; scan_strategy?: string
}) => http.post<unknown, { task_id: number; task_uuid: string; status: string; cidr: string }>(
  '/scan/trigger', body)

// ── 扫描目标 CRUD ──
export const listScanTargets = () => http.get<unknown, { targets: ScanTarget[] }>('/scan/targets')

export const createScanTarget = (body: Partial<ScanTarget>) =>
  http.post<unknown, ScanTarget>('/scan/targets', body)

export const updateScanTarget = (id: number, body: Partial<ScanTarget>) =>
  http.patch<unknown, ScanTarget>(`/scan/targets/${id}`, body)

export const deleteScanTarget = (id: number) =>
  http.delete<unknown, void>(`/scan/targets/${id}`)

// ── 任务/发现/服务/CVE 查询 ──
export const getScanTask = (id: number) => http.get<unknown, ScanTask>(`/scan/task/${id}`)

export const listScanTasks = (limit = 20, offset = 0, signal?: AbortSignal) =>
  http.get<unknown, { tasks: ScanTask[]; total?: number }>('/scan/tasks', { params: { limit, offset }, signal })

export const getScanFindings = (params: {
  ip?: string; service?: string; port?: number; task_id?: number;
  limit?: number; offset?: number
}, signal?: AbortSignal) => http.get<unknown, { findings: ScanFinding[]; total: number }>('/scan/findings', { params, signal })

export const listScanServices = (params: {
  vendor?: string; svc_type?: string; ip?: string; lifecycle_state?: string; limit?: number; offset?: number
}, signal?: AbortSignal) => http.get<unknown, { services: AiService[]; total: number }>('/scan/services', { params, signal })

export const listScanCves = (params: { service?: string; severity?: string; limit?: number; offset?: number }, signal?: AbortSignal) =>
  http.get<unknown, { cves: CveRecord[]; total: number }>('/scan/cve', { params, signal })
