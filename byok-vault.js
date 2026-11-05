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
    return subtle().importKey('raw', new TextEncoder().encode(pass), 'PBKDF2', false, ['deriveKey'])
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
        { name: 'AES-GCM', iv: iv }, key, new TextEncoder().encode(JSON.stringify(obj))
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
        var obj = JSON.parse(new TextDecoder().decode(pt));
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
    return subtle().digest('SHA-256', new TextEncoder().encode(key)).then(function (d) {
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
  function secureFetch(url, init) {
    init = init || {};
    return fetch(assertSecureEndpoint(url), {
      method: init.method, headers: init.headers, body: init.body, signal: init.signal,
      credentials: 'omit', referrerPolicy: 'no-referrer', cache: 'no-store'
    });
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
    var title = el('div', 'font-weight:600;margin-bottom:4px;');
    title.textContent = '密钥保护';
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
    root.appendChild(title); root.appendChild(status); root.appendChild(hint);
    root.appendChild(row); root.appendChild(msg);
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
    HANDLE_PREFIX: HANDLE_PREFIX, handleFor: handleFor, isHandle: isHandle, slotOf: slotOf,
    mountVaultControls: mountVaultControls
  };
})(typeof window !== 'undefined' ? window : globalThis);
