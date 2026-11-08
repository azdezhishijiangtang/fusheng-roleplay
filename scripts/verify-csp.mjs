// 校验 index.html 的 CSP sha256 是否与内联脚本一致。
// 用法：node scripts/verify-csp.mjs （建议每次改完 index.html 后运行）
import { readFileSync } from 'node:fs'
import { createHash } from 'node:crypto'

const html = readFileSync(new URL('../index.html', import.meta.url), 'utf8')
const csp = html.match(/Content-Security-Policy"\s+content="([^"]+)"/)?.[1] ?? ''
const declared = [...csp.matchAll(/'sha256-([^']+)'/g)].map((m) => m[1])
const inline = [...html.matchAll(/<script\b([^>]*)>([\s\S]*?)<\/script\s*>/gi)]
  .filter((m) => !/\bsrc=/.test(m[1]))
  .map((m) => m[2])
const computed = inline.map((code) => createHash('sha256').update(code, 'utf8').digest('base64'))
const stale = declared.filter((h) => !computed.includes(h))
if (stale.length > 0) {
  console.error('CSP 哈希与内联脚本不匹配 —— 浏览器会拒绝执行脚本！')
  console.error('  CSP 中声明:', declared)
  console.error('  实际计算值:', computed)
  console.error('请把 CSP 里的 sha256 替换为上面的实际计算值。')
  process.exit(1)
}
console.log('CSP 哈希校验通过（内联脚本', inline.length, '段）')
