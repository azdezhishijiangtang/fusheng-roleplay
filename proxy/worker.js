/*!
 * 浮生角色馆 · 自建 CORS 中转（Cloudflare Worker）
 *
 * 用途：让「智谱 GLM / OpenAI / Gemini」等不允许浏览器跨域直连（或国内网络不可达）
 *       的服务商，能在纯前端 BYOK 站点里正常使用。
 *
 * 工作原理：站点把请求发到
 *   https://<你的 Worker>/?target=<URL 编码后的完整 /chat/completions 地址>
 * Worker 校验目标域名在白名单内，原样转发（含 Authorization 与 SSE 流），
 * 并在响应上补齐 CORS 头。站点本身没有后端，中转是你自己部署的。
 *
 * 部署：
 *   1. Cloudflare Dashboard → Workers & Pages → Create Worker → 粘贴本文件 → Deploy
 *   2. 复制形如 https://xxx.xxx.workers.dev 的地址
 *   3. 站点「设置 API → CORS 中转」填入该地址即可，无需改动其它配置
 *
 * 隐私边界（务必阅读）：
 *   - 中转会接触明文 API Key 与聊天内容，因此**只部署在你自己的账号下**。
 *   - 绝不要把 Key 交给任何第三方公共 CORS 代理；那只等于把 Key 送人。
 *   - 白名单用于防止本 Worker 被当作开放代理滥用，请勿随意扩大。
 *   - 建议给 Worker 绑自定义域名并配置限流 / Cloudflare Access。
 */

/* 允许转发的目标主机（只允许 HTTPS）。新增服务商时在这里加一行即可。 */
const ALLOW_HOSTS = new Set([
  'api.openai.com',
  'api.deepseek.com',
  'open.bigmodel.cn',
  'api.z.ai',
  'api.moonshot.cn',
  'dashscope.aliyuncs.com',
  'generativelanguage.googleapis.com'
]);

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Authorization, Content-Type',
  'Access-Control-Max-Age': '86400'
};

/* 这些头要么由边缘重新生成，要么透传后会破坏流式响应 */
const STRIP_REQUEST_HEADERS = [
  'host', 'origin', 'referer', 'content-length', 'connection',
  'cf-connecting-ip', 'cf-ipcountry', 'cf-ray', 'cf-visitor',
  'x-forwarded-for', 'x-forwarded-proto', 'x-real-ip'
];
const STRIP_RESPONSE_HEADERS = [
  'content-length', 'content-encoding', 'transfer-encoding',
  'access-control-allow-credentials', 'access-control-allow-origin',
  'access-control-allow-methods', 'access-control-allow-headers',
  'access-control-max-age', 'connection'
];

function cors(headers) {
  const h = new Headers(headers || {});
  for (const k of Object.keys(CORS_HEADERS)) h.set(k, CORS_HEADERS[k]);
  return h;
}
function reply(body, status) {
  return new Response(body, { status: status, headers: cors() });
}

export default {
  async fetch(request) {
    /* 预检直接放行 —— 这正是智谱官方端点缺失的一步 */
    if (request.method === 'OPTIONS') return reply(null, 204);
    if (request.method !== 'POST' && request.method !== 'GET') {
      return reply('method not allowed', 405);
    }

    const self = new URL(request.url);
    const target = self.searchParams.get('target');
    if (!target) return reply('missing ?target=', 400);

    let dest;
    try { dest = new URL(target); } catch (e) { return reply('invalid target', 400); }
    if (dest.protocol !== 'https:' || !ALLOW_HOSTS.has(dest.hostname)) {
      return reply('target host not allowed', 403);
    }

    const headers = new Headers(request.headers);
    for (const k of STRIP_REQUEST_HEADERS) headers.delete(k);

    let upstream;
    try {
      upstream = await fetch(dest.toString(), {
        method: request.method,
        headers: headers,
        /* 请求体很小，缓冲后转发；响应体保持流式，SSE / 打字机效果不受影响 */
        body: request.method === 'POST' ? await request.arrayBuffer() : undefined,
        redirect: 'manual'
      });
    } catch (e) {
      return reply('upstream error: ' + (e && e.message ? e.message : String(e)), 502);
    }

    const out = new Headers(upstream.headers);
    for (const k of STRIP_RESPONSE_HEADERS) out.delete(k);
    for (const k of Object.keys(CORS_HEADERS)) out.set(k, CORS_HEADERS[k]);

    return new Response(upstream.body, {
      status: upstream.status,
      statusText: upstream.statusText,
      headers: out
    });
  }
};
