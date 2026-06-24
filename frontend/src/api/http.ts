import axios from 'axios'
import { ElMessage } from 'element-plus'

const http = axios.create({ baseURL: '/api/v1', timeout: 30000 })

http.interceptors.response.use(
  (res) => res.data,
  (err) => {
    // 主动取消的请求（AbortController）不算错误，静默 reject
    if (axios.isCancel(err) || err?.name === 'CanceledError' || err?.code === 'ERR_CANCELED') {
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
