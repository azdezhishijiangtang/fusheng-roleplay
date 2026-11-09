/*!
 * byok-vault.js — 纯前端 BYOK 密钥保险库（非模块 / 单 HTML 站点版）
 * 与 byokVault.ts 行为一致，挂载到 window.ByokVault。
 *
 * 默认零持久化：密钥仅存于闭包内存，刷新即失。
 * 可选加密暂存：PBKDF2-SHA256(310000) + AES-256-GCM，密文仅存 sessionStorage。
 * 自动锁定：隐藏超时 / 空闲超时 / pagehide / freeze。
 * 配套：严格 CSP、Referrer-Policy、全链路脱敏（见 SECURITY.md）。
 *
 * ⚠️ 边界：纯静态 BYOK 无法做到密码学意义上的绝对不泄露。XSS 若在密钥
 * 解锁期间执行脚本仍可 hook 请求。根治方案是服务端代理 + HttpOnly 会话。
 */
(function (global) {
  'use strict';

  var STORAGE_KEY = 'byok.vault.v1.blob';
  var ITER = 310000;
  var SALT_BYTES = 16, IV_BYTES = 12;
  var DEFAULT_TTL = 8 * 60 * 60 * 1000;
  var IDLE_LOCK = 15 * 60 * 1000;
  var HIDDEN_LOCK = 3 * 60 * 1000;
  var DEFAULT_SLOT = 'default';
  /* 句柄：运行时配置对象里代替明文 key 的标记，本身完全不能用于请求。 */
  var HANDLE_PREFIX = '@byok-vault:';
  function handleFor(slot) { return HANDLE_PREFIX + slot; }
  function isHandle(v) { return typeof v === 'string' && v.indexOf(HANDLE_PREFIX) === 0; }
  function slotOf(h) {
    if (isHandle(h)) return h.slice(HANDLE_PREFIX.length) || DEFAULT_SLOT;
    return h || DEFAULT_SLOT;
  }

  var memory = new Map();
  var idleTimer = null, hiddenTimer = null, guardsInstalled = false;
  var listeners = new Set();

  function subtle() {
    var c = global.crypto;
    if (!c || !c.subtle) throw new Error('当前环境不支持 Web Crypto：请用 HTTPS 或 localhost 打开站点。');
    return c.subtle;
  }
  function toB64(bytes) {
    var s = '';
    for (var i = 0; i < bytes.length; i++) s += String.fromCharCode(bytes[i]);
    return btoa(s);
  }
  function fromB64(s) {
    var bin = atob(s), out = new Uint8Array(bin.length);
    for (var i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  function randomBytes(n) { return global.crypto.getRandomValues(new Uint8Array(n)); }
  function deriveKey(pass, salt, iterations) {
    return subtle().importKey('raw', encodeUtf8(pass), 'PBKDF2', false, ['deriveKey'])
      .then(function (base) {
        return subtle().deriveKey(
          { name: 'PBKDF2', salt: salt, iterations: iterations, hash: 'SHA-256' },
          base, { name: 'AES-GCM', length: 256 }, false, ['encrypt', 'decrypt']
        );
      });
  }
  function emit() {
    var snap = state();
    listeners.forEach(function (cb) { try { cb(snap); } catch (e) {} });
  }
  function clearTimers() {
    if (idleTimer !== null) { clearTimeout(idleTimer); idleTimer = null; }
    if (hiddenTimer !== null) { clearTimeout(hiddenTimer); hiddenTimer = null; }
  }
  function touch() {
    if (idleTimer !== null) clearTimeout(idleTimer);
    idleTimer = setTimeout(lock, IDLE_LOCK);
  }
  function installGuards() {
    if (guardsInstalled || !global.document || !global.addEventListener) return;
    guardsInstalled = true;
    global.document.addEventListener('visibilitychange', function () {
      if (hiddenTimer !== null) { clearTimeout(hiddenTimer); hiddenTimer = null; }
      if (global.document.hidden) hiddenTimer = setTimeout(lock, HIDDEN_LOCK);
      else if (memory.size > 0) touch();
    });
    global.addEventListener('pagehide', lock);
    global.addEventListener('freeze', lock);
  }
  function storage() {
    try { return global.sessionStorage; } catch (e) { return null; }
  }
  function dropStored() {
    var s = storage(); if (s) { try { s.removeItem(STORAGE_KEY); } catch (e) {} }
  }
  function hasPersisted() {
    var s = storage(); if (!s) return false;
    var raw;
    try { raw = s.getItem(STORAGE_KEY); } catch (e) { return false; }
    if (!raw) return false;
    try {
      var blob = JSON.parse(raw);
      if (!blob.exp || Date.now() > blob.exp) { dropStored(); return false; }
      return true;
    } catch (e) { dropStored(); return false; }
  }
  function set(slot, apiKey) {
    var trimmed = String(apiKey || '').trim();
    if (!trimmed) throw new Error('密钥不能为空');
    dropStored(); // 内存状态变化即作废旧密文
    memory.set(slot || DEFAULT_SLOT, trimmed);
    installGuards(); touch(); emit();
  }
  function get(slot) {
    var key = memory.get(slotOf(slot)) || null;
    if (key) { installGuards(); touch(); }
    return key;
  }
  function has(slot) { return (memory.get(slotOf(slot)) || '').length > 0; }
  function clearSlot(slot) { dropStored(); memory.delete(slotOf(slot)); emit(); }
  function lock() { clearTimers(); memory = new Map(); emit(); }
  function purge() { clearTimers(); memory = new Map(); dropStored(); emit(); }
  function persist(pass, ttlMs) {
    if (!pass || pass.length < 8) return Promise.reject(new Error('解锁口令至少 8 位'));
    if (memory.size === 0) return Promise.reject(new Error('当前没有已解锁的密钥，无法暂存'));
    var s = storage();
    if (!s) return Promise.reject(new Error('当前环境不支持会话存储'));
    var salt = randomBytes(SALT_BYTES), iv = randomBytes(IV_BYTES);
    var obj = {}; memory.forEach(function (v, k) { obj[k] = v; });
    return deriveKey(pass, salt, ITER).then(function (key) {
      return subtle().encrypt(
        { name: 'AES-GCM', iv: iv }, key, encodeUtf8(JSON.stringify(obj))
      );
    }).then(function (ct) {
      var blob = {
        v: 1, alg: 'PBKDF2-SHA256/AES-256-GCM', iter: ITER,
        salt: toB64(salt), iv: toB64(iv), ct: toB64(new Uint8Array(ct)),
        exp: Date.now() + (ttlMs || DEFAULT_TTL), slots: memory.size
      };
      s.setItem(STORAGE_KEY, JSON.stringify(blob));
      emit();
    });
  }
  function unlock(pass) {
    var s = storage(); if (!s || !pass) return Promise.resolve(false);
    var raw;
    try { raw = s.getItem(STORAGE_KEY); } catch (e) { return Promise.resolve(false); }
    if (!raw) return Promise.resolve(false);
    var blob;
    try { blob = JSON.parse(raw); } catch (e) { purge(); return Promise.resolve(false); }
    if (blob.v !== 1 || !blob.exp || Date.now() > blob.exp) { purge(); return Promise.resolve(false); }
    return deriveKey(pass, fromB64(blob.salt), blob.iter || ITER)
      .then(function (key) {
        return subtle().decrypt({ name: 'AES-GCM', iv: fromB64(blob.iv) }, key, fromB64(blob.ct));
      })
      .then(function (pt) {
        var obj = JSON.parse(decodeUtf8(new Uint8Array(pt)));
        var restored = new Map();
        Object.keys(obj).forEach(function (k) {
          if (typeof obj[k] === 'string' && obj[k].length > 0) restored.set(k, obj[k]);
        });
        if (restored.size === 0) return false;
        memory = restored; installGuards(); touch(); emit(); return true;
      })
      .catch(function () { return false; }); // GCM 认证失败 = 口令错误或密文被改
  }
  function state() {
    var expiresAt = null, s = storage();
    if (s) {
      try { var raw = s.getItem(STORAGE_KEY); if (raw) expiresAt = JSON.parse(raw).exp || null; }
      catch (e) { expiresAt = null; }
    }
    return {
      unlocked: memory.size > 0,
      persisted: hasPersisted(),
      slots: Array.from(memory.keys()),
      expiresAt: expiresAt
    };
  }
  function subscribe(cb) { listeners.add(cb); return function () { listeners.delete(cb); }; }
  function fingerprint(slot) {
    var key = memory.get(slotOf(slot));
    if (!key) return Promise.resolve(null);
    return subtle().digest('SHA-256', encodeUtf8(key)).then(function (d) {
      return Array.from(new Uint8Array(d).slice(0, 4))
        .map(function (b) { return b.toString(16).padStart(2, '0'); }).join('');
    });
  }
  function mask(key) {
    var s = String(key || '').trim();
    if (!s) return '';
    if (s.length <= 8) return '••••••••';
    return s.slice(0, 3) + '••••••••' + s.slice(-4);
  }
  function assertSecureEndpoint(url) {
    var u = String(url || '').trim(), parsed;
    try { parsed = new URL(u); } catch (e) { throw new Error('API 地址不是合法的 URL'); }
    var local = parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1';
    if (parsed.protocol !== 'https:' && !local) {
      throw new Error('安全策略：API 地址必须使用 HTTPS，禁止通过明文 HTTP 发送密钥。');
    }
    return u;
  }
  function authHeaders(handleOrSlot) {
    var key = get(slotOf(handleOrSlot));
    if (!key) throw new Error('密钥已锁定，请在设置中重新输入 API Key。');
    return { Authorization: 'Bearer ' + key };
  }
  /* ================================================================
   * 浏览器兼容层：只做特性检测，不解析 UA（国产/定制内核 UA 千变万化）
   * 覆盖：ReadableStream / TextDecoder / AbortController / fetch 缺失，
   *       以及流式响应不支持时的一次性读取回退。
   * ================================================================ */
  var caps = {
    fetch: typeof fetch === 'function',
    xhr: typeof XMLHttpRequest !== 'undefined',
    abort: typeof AbortController !== 'undefined',
    readableStream: typeof ReadableStream !== 'undefined',
    textDecoder: typeof TextDecoder !== 'undefined',
    textEncoder: typeof TextEncoder !== 'undefined'
  };
  if (!caps.abort) {
    function LegacyAbortController() {
      var self = this;
      this.signal = {
        aborted: false, onabort: null,
        addEventListener: function () {}, removeEventListener: function () {},
        dispatchEvent: function () { return false; }
      };
      this.abort = function () {
        self.signal.aborted = true;
        if (typeof self.signal.onabort === 'function') {
          try { self.signal.onabort(); } catch (e) {}
        }
      };
    }
    global.AbortController = LegacyAbortController;
  }
  function canReadStream(res) {
    if (!caps.readableStream || !caps.textDecoder) return false;
    return !!(res && res.body && typeof res.body.getReader === 'function');
  }
  function readResponseText(res) {
    if (res && typeof res.text === 'function') {
      try { return res.text(); } catch (e) {}
    }
    return Promise.resolve((res && res._compatText) || '');
  }
  function parsePayloads(text) {
    var src = text || '';
    var trimmed = src.replace(/^\s+|\s+$/g, '');
    if (!trimmed) return [];
    if (trimmed.charAt(0) === '{' || trimmed.charAt(0) === '[') return [trimmed];
    var out = [];
    src.split(/\r?\n/).forEach(function (raw) {
      var line = raw.replace(/^\s+|\s+$/g, '');
      if (line.indexOf('data:') !== 0) return;
      var d = line.slice(5).replace(/^\s+|\s+$/g, '');
      if (d && d !== '[DONE]') out.push(d);
    });
    return out;
  }
  /** TextEncoder 缺失时的 UTF-8 兜底编码（含 4 字节字符与代理对） */
  function encodeUtf8(text) {
    if (caps.textEncoder) return new TextEncoder().encode(text);
    var out = [], i = 0, cp, low;
    for (i = 0; i < text.length; i++) {
      cp = text.charCodeAt(i);
      if (cp >= 0xd800 && cp <= 0xdbff && i + 1 < text.length) {
        low = text.charCodeAt(i + 1);
        if (low >= 0xdc00 && low <= 0xdfff) {
          cp = 0x10000 + ((cp - 0xd800) << 10) + (low - 0xdc00);
          i++;
        }
      }
      if (cp < 0x80) out.push(cp);
      else if (cp < 0x800) out.push(0xc0 | (cp >> 6), 0x80 | (cp & 0x3f));
      else if (cp < 0x10000) out.push(0xe0 | (cp >> 12), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
      else out.push(0xf0 | (cp >> 18), 0x80 | ((cp >> 12) & 0x3f), 0x80 | ((cp >> 6) & 0x3f), 0x80 | (cp & 0x3f));
    }
    return new Uint8Array(out);
  }
  function decodeUtf8(bytes) {
    if (caps.textDecoder) return new TextDecoder().decode(bytes);
    var out = '', i = 0;
    while (i < bytes.length) {
      var b = bytes[i];
      if (b < 0x80) { out += String.fromCharCode(b); i++; continue; }
      var n = 0, cp = 0;
      if (b >= 0xc0 && b < 0xe0) { n = 2; cp = b & 0x1f; }
      else if (b >= 0xe0 && b < 0xf0) { n = 3; cp = b & 0x0f; }
      else if (b >= 0xf0 && b < 0xf8) { n = 4; cp = b & 0x07; }
      else { out += '\ufffd'; i++; continue; }
      if (i + n > bytes.length) { out += '\ufffd'; break; }
      for (var k = 1; k < n; k++) cp = (cp << 6) | (bytes[i + k] & 0x3f);
      i += n;
      if (cp > 0xffff) { cp -= 0x10000; out += String.fromCharCode(0xd800 + (cp >> 10), 0xdc00 + (cp & 0x3ff)); }
      else out += String.fromCharCode(cp);
    }
    return out;
  }
  function legacyFetch(url, init) {
    return new Promise(function (resolve, reject) {
      if (!caps.xhr) { reject(new Error('当前浏览器缺少 fetch 与 XMLHttpRequest，请升级系统浏览器后重试。')); return; }
      try {
        var xhr = new XMLHttpRequest();
        xhr.open(init.method || 'GET', url, true);
        if (init.headers && typeof init.headers === 'object') {
          Object.keys(init.headers).forEach(function (k) {
            try { xhr.setRequestHeader(k, init.headers[k]); } catch (e) {}
          });
        }
        xhr.timeout = 45000;
        xhr.onload = function () {
          var text = xhr.responseText || '';
          resolve({
            ok: xhr.status >= 200 && xhr.status < 300,
            status: xhr.status, statusText: xhr.statusText, body: null,
            headers: { get: function (n) { return xhr.getResponseHeader(n); } },
            json: function () { return Promise.resolve(JSON.parse(text)); },
            text: function () { return Promise.resolve(text); },
            clone: function () { return this; },
            _compatText: text
          });
        };
        xhr.onerror = function () { reject(new Error('网络请求失败：请检查接口地址、网络，以及服务商是否允许浏览器跨域（CORS）。')); };
        xhr.ontimeout = function () { reject(new Error('连接超时（45 秒）：请检查接口地址与网络。')); };
        xhr.send(init.body || null);
      } catch (e) { reject(e); }
    });
  }
  function secureFetch(url, init) {
    init = init || {};
    var target = assertSecureEndpoint(url);
    if (!caps.fetch) return legacyFetch(target, init);
    var opts = {
      method: init.method, headers: init.headers, body: init.body,
      credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store'
    };
    if (caps.abort && init.signal) opts.signal = init.signal;
    if (!caps.abort) {
      return Promise.race([
        fetch(target, opts),
        new Promise(function (_, reject) {
          setTimeout(function () { reject(new Error('连接超时（45 秒）：请检查接口地址与网络。')); }, 45000);
        })
      ]);
    }
    return fetch(target, opts);
  }
  var SENSITIVE = /(apikey|api_key|passphrase|password|secret|token|pat|authorization|bearer)/i;
  function redact(value) {
    function walk(v) {
      if (Array.isArray(v)) return v.map(walk);
      if (v && typeof v === 'object') {
        var out = {};
        Object.keys(v).forEach(function (k) { out[k] = SENSITIVE.test(k) ? '' : walk(v[k]); });
        return out;
      }
      return v;
    }
    return walk(value);
  }

  /* 通用控制面板：原生 DOM，不依赖框架，5 个站点共用一个容器即可。 */
  function mountVaultControls(host, onChange) {
    var root = global.document.createElement('div');
    root.setAttribute('data-byok-vault', '');
    root.style.cssText = 'border:1px solid rgba(127,127,127,.35);border-radius:10px;padding:12px;margin:10px 0;font-size:12px;line-height:1.6;';
    function el(tag, css) {
      var e = global.document.createElement(tag);
      if (css) e.style.cssText = css;
      return e;
    }
    var titleRow = global.document.createElement('div');
    titleRow.style.cssText = 'display:flex;align-items:center;justify-content:space-between;gap:8px;margin-bottom:4px;';
    var title = global.document.createElement('div');
    title.style.cssText = 'font-weight:600;';
    title.textContent = '密钥保护';

    /* 「?」帮助按钮：点开 / 收起解锁口令机制的白话说明（原生 DOM，不拼 HTML） */
    var panelId = 'byok-help-' + Math.random().toString(36).slice(2, 9);
    var helpBtn = global.document.createElement('button');
    helpBtn.type = 'button';
    helpBtn.textContent = '?';
    helpBtn.title = '这是什么？点开看详细说明';
    helpBtn.setAttribute('aria-label', '查看密钥保护与解锁口令机制说明');
    helpBtn.setAttribute('aria-expanded', 'false');
    helpBtn.setAttribute('aria-controls', panelId);
    helpBtn.style.cssText = 'flex:0 0 auto;width:20px;height:20px;line-height:18px;padding:0;border-radius:50%;border:1px solid rgba(127,127,127,.55);background:transparent;color:inherit;cursor:pointer;font-size:12px;font-weight:700;';

    var help = global.document.createElement('div');
    help.id = panelId;
    help.style.cssText = 'display:none;max-height:320px;overflow:auto;margin:10px 0 2px;padding:12px 14px;border-radius:8px;border:1px solid rgba(127,127,127,.3);background:rgba(127,127,127,.06);line-height:1.75;';
    helpBtn.addEventListener('click', function () {
      var open = help.style.display === 'none';
      help.style.display = open ? '' : 'none';
      helpBtn.setAttribute('aria-expanded', String(open));
    });

    var HELP_SECTIONS = [
      { h: '一句话：这个「口令」到底是什么？', lines: [
        '它是你给「浏览器里的临时保险箱」设的开箱密码，只用来把 API Key 临时锁在当前标签页里。',
        '它不是网站密码——本站没有账号、不用注册登录；也不是 API Key——API Key 是服务商给你的 sk-… 那一串。',
        '不填它，网站照常能用；填它，只是为了刷新页面后不用重新粘贴 API Key。',
      ] },
      { h: '设 / 不设，差别在哪？', lines: [
        '不设（默认，最安全）：Key 只放在内存里，刷新或关掉标签页立刻消失，代价是每次刷新要重贴一次 Key。',
        '设（点「会话内记住」）：用口令把 Key 加密成 AES-256-GCM 密文，暂存在当前标签页；刷新后输口令解锁，不用重贴 Key。关掉标签页一样全部消失。',
        '两种方式都不会把明文 Key 写进硬盘，导出备份也永远不含 Key 和口令。',
        '加密用 PBKDF2-SHA256（31 万轮）派生口令，再以 AES-256-GCM 加密；派生的密钥不可导出，口令和明文 Key 都不落盘。',
        '拿不准就用默认（不设）——只是多贴一次 Key，换来电脑上不留任何痕迹。',
      ] },
      { h: '怎么用？', lines: [
        '只想临时用一次：什么都不用做，直接在上面填 API Key 开始提问。',
        '想免重贴：填好 API Key → 在下面输入框填一串至少 8 位的口令 → 点「会话内记住」。',
        '刷新回来后：输入同一口令 → 点「解锁」，即可继续提问。',
        '用完想收工：「立即锁定」是临时锁屏（密文还在）；「彻底清除」是内存与密文一起抹掉，不可恢复。',
        '换了 API Key、或者用完公共电脑，请用「彻底清除」并关掉标签页。',
      ] },
      { h: '它会自动锁上吗？会', lines: [
        '空闲 15 分钟没有任何 AI 请求、切到别的标签页或最小化 3 分钟、刷新或关闭页面，都会自动清空内存里的明文 Key。',
        '加密暂存最长 8 小时，过期自动作废，不能延长。',
        '只要重新粘贴 / 修改 API Key，旧的暂存立刻作废，需要重新设一次。',
      ] },
      { h: '常见问题', lines: [
        '口令忘了怎么办？——无法找回，本站不存口令、也没有找回密码。但一点都不严重：点「彻底清除」，重新粘贴 API Key，再设个新口令即可；你的 Key 在服务商控制台还在。',
        '口令会上传吗？——不会。本站没有服务器，口令只在浏览器本地参与加密计算，从不进入任何网络请求，也不写入 localStorage。',
        '要设多复杂？——至少 8 位，别用生日、别和常用账号密码相同即可。',
        '公共电脑怎么办？——不要设口令，用完点「彻底清除」并关闭标签页。',
        '导出备份会带出密钥吗？——不会，导出文件永远不含 API Key 和口令。',
      ] },
      { h: '请如实了解的安全边界', lines: [
        '纯前端绕不开一个事实：发请求那一刻，浏览器必须短暂拿着明文 Key。若页面被注入恶意脚本（XSS），攻击者在解锁期间仍可能读到它。',
        '本机制做的是把「长期躺在硬盘上的明文」变成「短暂存在于内存的明文」，并配合站点严格 CSP 尽量堵死注入，但不能宣称绝对不会泄露。',
        '请务必使用额度受限、可随时撤销的专用子密钥，不要用主账号密钥，并定期轮换。',
        '要让浏览器永不持有明文，唯一根治方案是服务端代理加 HttpOnly 会话；本站刻意不采用，以保持纯静态、零收集。',
      ] },
    ];
    for (var sec of HELP_SECTIONS) {
      var hh = global.document.createElement('div');
      hh.style.cssText = 'font-weight:600;margin:10px 0 4px;';
      hh.textContent = sec.h;
      help.appendChild(hh)
      var ul = global.document.createElement('ul');
      ul.style.cssText = 'margin:0;padding-left:18px;';
      for (var line of sec.lines) {
        var li = global.document.createElement('li');
        li.style.cssText = 'margin:2px 0;';
        li.textContent = line;
        ul.appendChild(li)
      };
      help.appendChild(ul)
    };
    var helpFoot = global.document.createElement('div');
    helpFoot.style.cssText = 'opacity:.7;margin-top:8px;';
    helpFoot.textContent = '完整技术说明见项目文档《密钥保护说明.md》。';
    help.appendChild(helpFoot)
    titleRow.appendChild(title); titleRow.appendChild(helpBtn)
    var status = el('div');
    var hint = el('div', 'opacity:.75;margin:6px 0;');
    hint.textContent = '默认零持久化：密钥只存在内存中，刷新或关闭页面即消失，绝不写入 localStorage。仅当你主动设置口令并点「会话内记住」时，才会以 AES-256-GCM 密文暂存于本标签页。';
    var row = el('div', 'display:flex;gap:6px;flex-wrap:wrap;margin-top:8px;');
    var input = el('input', 'flex:1 1 150px;min-width:120px;padding:6px 8px;border:1px solid rgba(127,127,127,.4);border-radius:6px;background:transparent;color:inherit;font-size:12px;');
    input.type = 'password'; input.autocomplete = 'new-password';
    var msg = el('div', 'margin-top:6px;min-height:1em;');
    function say(text) { msg.textContent = text; }
    function btn(label, fn) {
      var b = el('button', 'padding:6px 10px;border:1px solid rgba(127,127,127,.4);border-radius:6px;background:transparent;color:inherit;cursor:pointer;font-size:12px;');
      b.type = 'button'; b.textContent = label;
      b.addEventListener('click', fn);
      return b;
    }
    var bRemember = btn('会话内记住', function () {
      persist(input.value).then(function () {
        input.value = '';
        say('已加密暂存于本标签页。刷新后输入同一口令即可解锁；关闭标签页自动失效。');
      }).catch(function (e) { say(e && e.message ? e.message : '暂存失败'); });
    });
    var bUnlock = btn('解锁', function () {
      unlock(input.value).then(function (ok) {
        input.value = '';
        say(ok ? '已解锁，密钥已恢复到内存。' : '口令错误、暂存已过期或密文被改动。');
        if (ok && onChange) onChange();
      });
    });
    var bLock = btn('立即锁定', function () { lock(); say('已锁定：内存中的密钥已清除。'); if (onChange) onChange(); });
    var bPurge = btn('彻底清除', function () { purge(); say('已彻底清除：内存与加密暂存均已销毁。'); if (onChange) onChange(); });
    row.appendChild(input); row.appendChild(bRemember); row.appendChild(bUnlock);
    row.appendChild(bLock); row.appendChild(bPurge);
    root.appendChild(titleRow); root.appendChild(status); root.appendChild(hint);
    root.appendChild(row); root.appendChild(msg); root.appendChild(help);
    host.replaceChildren(root);

    function render(s) {
      var until = s.expiresAt ? new Date(s.expiresAt).toLocaleTimeString('zh-CN', { hour: '2-digit', minute: '2-digit' }) : '';
      if (s.unlocked) {
        status.textContent = '● 已解锁（' + s.slots.length + ' 把密钥在内存中）' + (s.persisted ? ' · 已加密暂存至 ' + until : '');
        status.style.color = '#2e9e6b';
      } else if (s.persisted) {
        status.textContent = '● 已锁定 · 存在加密暂存（至 ' + until + '），输入口令解锁';
        status.style.color = '#c08a2e';
      } else {
        status.textContent = '● 已锁定 · 无暂存，请重新输入 API Key';
        status.style.color = '#b45b5b';
      }
      input.placeholder = s.persisted && !s.unlocked ? '输入解锁口令' : '设置解锁口令（至少 8 位）';
      bRemember.style.display = s.unlocked ? '' : 'none';
      bUnlock.style.display = s.persisted && !s.unlocked ? '' : 'none';
      bLock.style.display = s.unlocked ? '' : 'none';
      bPurge.style.display = (s.unlocked || s.persisted) ? '' : 'none';
    }
    var unsub = subscribe(render);
    render(state());
    return function () { unsub(); root.remove(); };
  }

  global.ByokVault = {
    set: set, get: get, has: has, clearSlot: clearSlot, lock: lock, purge: purge,
    hasPersisted: hasPersisted, persist: persist, unlock: unlock, state: state,
    subscribe: subscribe, fingerprint: fingerprint, mask: mask,
    assertSecureEndpoint: assertSecureEndpoint, authHeaders: authHeaders,
    secureFetch: secureFetch, redact: redact,
    caps: caps, canReadStream: canReadStream, readResponseText: readResponseText,
    parsePayloads: parsePayloads, decodeUtf8: decodeUtf8, encodeUtf8: encodeUtf8,
    HANDLE_PREFIX: HANDLE_PREFIX, handleFor: handleFor, isHandle: isHandle, slotOf: slotOf,
    mountVaultControls: mountVaultControls
  };
})(typeof window !== 'undefined' ? window : globalThis);
