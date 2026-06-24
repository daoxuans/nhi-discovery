import axios from 'axios'
import { ElMessage } from 'element-plus'

const http = axios.create({ baseURL: '/api/v1', timeout: 30000 })

// 允许单个请求标记 silent=true，跳过全局错误 toast（用于高频轮询如 health）
// 用法：http.get('/x', { silent: true } as any)
declare module 'axios' {
  interface AxiosRequestConfig {
    silent?: boolean
  }
}

http.interceptors.response.use(
  (res) => res.data,
  (err) => {
    // 主动取消的请求（AbortController）不算错误，静默 reject
    if (axios.isCancel(err) || err?.name === 'CanceledError' || err?.code === 'ERR_CANCELED') {
      return Promise.reject(err)
    }
    // silent 请求（如 health 10s 轮询）不弹 toast，避免后端重启时每 10s 弹一次错误（F9）
    if (err?.config?.silent) {
      return Promise.reject(err)
    }
    // FastAPI 422 验证错误：detail 是数组 [{loc,msg,...}]，需展开成可读字符串
    let msg: any = err.response?.data?.detail
    if (Array.isArray(msg)) {
      msg = msg.map((d: any) => d?.msg).filter(Boolean).join('; ')
    }
    if (typeof msg === 'object' && msg !== null) msg = JSON.stringify(msg)
    msg = msg || err.message || '请求失败'
    ElMessage.error(msg)
    return Promise.reject(err)
  }
)

export default http
