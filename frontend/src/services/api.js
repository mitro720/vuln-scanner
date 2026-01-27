import axios from 'axios'

const API_URL = import.meta.env.VITE_API_URL || 'http://localhost:5000/api'

const api = axios.create({
    baseURL: API_URL,
    headers: {
        'Content-Type': 'application/json',
    },
})

// Request interceptor for adding auth token
api.interceptors.request.use(
    (config) => {
        const token = localStorage.getItem('token')
        if (token) {
            config.headers.Authorization = `Bearer ${token}`
        }
        return config
    },
    (error) => {
        return Promise.reject(error)
    }
)

// Response interceptor for error handling
api.interceptors.response.use(
    (response) => response.data,
    (error) => {
        const message = error.response?.data?.error?.message || 'An error occurred'
        console.error('API Error:', message)
        return Promise.reject(error)
    }
)

// Scan API
export const scanAPI = {
    getAll: () => api.get('/scans'),
    getById: (id) => api.get(`/scans/${id}`),
    create: (data) => api.post('/scans', data),
    update: (id, data) => api.put(`/scans/${id}`, data),
    delete: (id) => api.delete(`/scans/${id}`),
    getFindings: (id) => api.get(`/scans/${id}/findings`),
}

// Findings API
export const findingsAPI = {
    getAll: (params) => api.get('/findings', { params }),
    getById: (id) => api.get(`/findings/${id}`),
    update: (id, data) => api.put(`/findings/${id}`, data),
}

// Health check
export const healthCheck = () => api.get('/health')

export default api
