import { createRouter, createWebHistory } from 'vue-router'

// 模块增强：让 RouteMeta 支持 title/icon/hidden 字段，消除模板里的 as any
declare module 'vue-router' {
  interface RouteMeta {
    title?: string
    icon?: string
    hidden?: boolean
  }
}

const routes = [
  { path: '/', redirect: '/dashboard' },
  { path: '/dashboard', name: 'dashboard', component: () => import('@/views/DashboardView.vue'),
    meta: { title: '资产总览', icon: 'Odometer' } },
  { path: '/probe/endpoints', name: 'probe-endpoints', component: () => import('@/views/ProbeEndpointsView.vue'),
    meta: { title: '探针识别资产', icon: 'Connection' } },
  { path: '/probe/endpoint/:ip', name: 'probe-endpoint-detail', component: () => import('@/views/EndpointDetailView.vue'),
    meta: { title: '端点画像', hidden: true } },
  { path: '/scan/assets', name: 'scan-assets', component: () => import('@/views/ScanAssetsView.vue'),
    meta: { title: '主动扫描资产', icon: 'Search' } },
  { path: '/scan/config', name: 'scan-config', component: () => import('@/views/ScanConfigView.vue'),
    meta: { title: '扫描配置', icon: 'Setting' } },
  { path: '/fusion', name: 'fusion', component: () => import('@/views/FusionView.vue'),
    meta: { title: '融合资产', icon: 'Share' } },
]

const router = createRouter({
  history: createWebHistory(),
  routes,
  scrollBehavior: () => ({ top: 0 }),
})

export { routes }
export default router
