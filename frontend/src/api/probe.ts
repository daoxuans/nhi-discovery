import http from './http'

export interface HealthResp {
  status: string
  db_size_bytes: number
  tables: Record<string, number>
  probe_consumer: string
  probe_event_count: number
  db_writer_queue_depth: number
  ai_writer_queue_depth?: number
  ai_writer_written?: number
  ai_writer_dropped?: number
  scan_scheduler: string
}

// silent=true：高频轮询专用，失败不弹全局错误 toast（避免后端重启时每 10s 弹一次，F9）
export const getHealth = () => http.get<unknown, HealthResp>('/health', { silent: true } as any)

export interface AiStatsResp {
  total: number
  confirmed: number
  percentage: number
  vendor_counts: Record<string, number>
  service_counts: Record<string, number>
  agent_counts: Record<string, number>
  svc_type_counts: Record<string, number>
  top_ja4: { ja4: string; count: number }[]
  top_hostnames: { hostname: string; count: number }[]
}

export const getAiStats = (time_range = '24h', signal?: AbortSignal) =>
  http.get<unknown, AiStatsResp>('/ai/events/stats', { params: { time_range }, signal })

export interface AiEndpoint {
  id: number
  ip: string
  role: 'agent' | 'service'
  name: string
  vendor: string | null
  category: string | null
  ja4_list: string
  user_agent: string | null
  models: string
  flow_count: number
  first_seen: string
  last_seen: string
  lifecycle_state: string
  scan_seen: number
  fused_confidence: number | null
}

/** 端点画像响应（/ai/endpoint/{ip}） */
export interface EndpointDetail {
  ip: string
  agents: AiEndpoint[]
  services: AiEndpoint[]
  scan_services: Array<{
    port: number
    service: string
    vendor: string | null
    version: string | null
    lifecycle_state: string
    scan_count: number
    last_seen: string
  }>
  timeline: Array<{
    occurred_at: string
    event_type: string
    old_state: string | null
    new_state: string | null
    detail: string | null
  }>
}

export const getAiEndpoints = (params: {
  role?: string; ip?: string; name?: string; limit?: number; offset?: number
}, signal?: AbortSignal) => http.get<unknown, { endpoints: AiEndpoint[]; total: number }>('/ai/endpoints', { params, signal })

export const getAiEndpoint = (ip: string) => http.get<unknown, EndpointDetail>(`/ai/endpoint/${ip}`)

export interface AiEvent {
  id: number
  flow_id: number
  src_ip: string
  dst_ip: string
  proto: string | null
  hostname: string | null
  ai_vendor: string | null
  ai_service: string | null
  ai_agent: string | null
  ai_agent_score: number | null
  ja4: string | null
  user_agent: string | null
  event_type: string
  created_at: string
}

export const getAiEvents = (params: {
  ai_agent?: string; ai_vendor?: string; ai_service?: string; src_ip?: string;
  limit?: number; offset?: number
}) => http.get<unknown, { events: AiEvent[]; total: number; limit: number; offset: number }>(
  '/ai/events', { params })
