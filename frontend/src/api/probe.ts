import http from './http'

export interface HealthResp {
  status: string
  db_size_bytes: number
  tables: Record<string, number>
  probe_consumer: string
  probe_event_count: number
  db_writer_queue_depth: number
  scan_scheduler: string
}

export const getHealth = () => http.get<unknown, HealthResp>('/health')

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

export const getAiStats = (time_range = '24h') =>
  http.get<unknown, AiStatsResp>('/ai/events/stats', { params: { time_range } })

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

export const getAiEndpoints = (params: {
  role?: string; ip?: string; name?: string; limit?: number; offset?: number
}) => http.get<unknown, { endpoints: AiEndpoint[]; total: number }>('/ai/endpoints', { params })

export const getAiEndpoint = (ip: string) => http.get<unknown, any>(`/ai/endpoint/${ip}`)

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
