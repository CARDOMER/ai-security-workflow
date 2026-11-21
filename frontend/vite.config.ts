import { defineConfig, loadEnv } from 'vite'

export default defineConfig(({ mode }) => {
  const env = loadEnv(mode, '.', 'WORKFLOW_')
  const proxy = { '/api': env.WORKFLOW_BACKEND_URL || 'http://127.0.0.1:8000' }
  return {
    server: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
    preview: { host: '127.0.0.1', port: 5173, strictPort: true, proxy },
  }
})
