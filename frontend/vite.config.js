import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'
import { readFile, writeFile } from 'node:fs/promises'

const routeEntries = ['dashboard','users','websites','applications','tools','storefront','files','databases','backups','domains','mail','mail-security','firewall','storage','updates','certificates','support','activity','open-source','settings']

function routeHtmlEntries() {
  return { name: 'masspanel-route-html', async closeBundle() {
    const html = await readFile('dist/index.html', 'utf8')
    await Promise.all(routeEntries.map((route) => writeFile(`dist/${route}.html`, html)))
  } }
}

export default defineConfig({
  plugins: [react(), routeHtmlEntries()],
  build: { outDir: 'dist', sourcemap: false, emptyOutDir: false },
  server: { proxy: { '/api': 'http://127.0.0.1:8100' } },
})
