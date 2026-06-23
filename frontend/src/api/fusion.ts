import http from './http'

export interface FusedAsset {
  ip: string
  port: number
  service: string
  vendor: string | null
  svc_type: string | null
  version: string | null
  models: string | null
  lifecycle_state: string
  scan_count: number
  scan_last_seen: string
  probe_seen: number
  probe_last_flow: string | null
  fused_confidence: number | null
  risk_level: string | null
  cve_count: number
  probe_flow_count: number | null
  probe_last_seen: string | null
  probe_endpoint_name: string | null
}

export const getFusedAssets = (params: {
  ip?: string; svc_type?: string; source?: string;
  risk_level?: string; lifecycle_state?: string; limit?: number; offset?: number
}) => http.get<unknown, { assets: FusedAsset[]; total: number }>('/assets/fused', { params })

export interface FlowStats {
  total: number
  protocols: { name: string; count: number }[]
  categories: { name: string; count: number }[]
  detection: Record<string, number>
  risks: Record<string, number>
}

export const getFlowStats = () => http.get<unknown, FlowStats>('/flows/stats')
