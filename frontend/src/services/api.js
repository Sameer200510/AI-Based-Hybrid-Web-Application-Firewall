import axios from 'axios'

const api = axios.create({
  baseURL: '/api/v1',
  headers: {
    'Content-Type': 'application/json'
  }
})

export const getDashboardStats = () => api.get('/dashboard/stats')
export const getAttackTimeline = () => api.get('/dashboard/timeline')
export const inspectRequest = (payload) => api.post('/waf/inspect', payload)
export const simulateAttack = (attackType) => api.post('/waf/simulate', { attack_type: attackType })
export const getLogs = (params) => api.get('/logs', { params })
export const getRules = () => api.get('/rules')
export const createRule = (ruleData) => api.post('/rules', ruleData)
export const toggleRule = (id) => api.post(`/rules/${id}/toggle`)
export const deleteRule = (id) => api.delete(`/rules/${id}`)
export const runIEEEBenchmark = (samples = 400) => api.post('/ml/evaluate', { samples })
export const trainLightGBM = () => api.post('/ml/train')

export default api
