import { createRouter, createWebHistory } from 'vue-router'

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'dashboard', component: () => import('@/views/DashboardView.vue'),
    meta: { title: '资产总览', icon: 'Odometer' } },
  { path: '/probe/endpoints', name: 'probe-endpoints', component: () => import('@/views/ProbeEndpointsView.vue'),
    meta: { title: '探针识别资产', icon: 'Connection' } },
  { path: '/probe/endpoint/:ip', name: 'probe-endpoint-detail', component: () => import('@/views/EndpointDetailView.vue'),
    meta: { title: '端点画像', hidden: true } },
  { path: '/scan', name: 'scan', component: () => import('@/views/ScanView.vue'),
    meta: { title: '主动扫描', icon: 'Search' } },
  { path: '/fusion', name: 'fusion', component: () => import('@/views/FusionView.vue'),
    meta: { title: '融合资产', icon: 'Share' } },
]

const router = createRouter({ history: createWebHistory(), routes })

export default router
