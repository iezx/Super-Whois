/**
 * Super Whois Chrome Extension — popup.js
 * Features: i18n, auto-query, subdomain detection, semantic EPP status pills, DNS records
 */
(function () {
  'use strict';

  const $ = (id) => document.getElementById(id);
  const apiUrlInput      = $('api-url');
  const apiKeyInput      = $('api-key');
  const domainInput      = $('domain-input');
  const lookupBtn        = $('lookup-btn');
  const resultArea       = $('result-area');
  const settingsPanel    = $('settings-panel');
  const settingsToggle   = $('settings-toggle');
  const langSelector     = $('lang-selector');
  const saveBtn          = $('save-settings');
  const autoQueryToggle  = $('auto-query-toggle');
  const subdomainToggle  = $('subdomain-toggle');
  const subdomainHint    = $('subdomain-hint');
  const subdomainText    = $('subdomain-hint-text');
  const apexLink         = $('apex-link');
  const dismissSubdomain = $('dismiss-subdomain');

  // ── i18n ─────────────────────────────────────────────────────────────
  const LANGS = {
    en: {
      s_api_url: 'API Base URL',
      s_api_hint: 'Your Super Whois API endpoint',
      s_api_key: 'API Key (optional)',
      s_key_hint: 'Leave empty for unauthenticated access',
      s_lang: 'Language',
      s_auto_query: 'Auto-query current domain',
      s_auto_query_sub: 'Lookup when opening the extension',
      s_subdomain_hint: 'Subdomain → apex suggestion',
      s_subdomain_hint_sub: 'Ask to query apex domain for subdomains',
      s_save: 'Save',
      s_saved: 'Saved!',
      lookup: 'Lookup',
      empty: 'Enter a domain, IP, or ASN\nto look up WHOIS info',
      subdomain_prompt: 'Subdomain detected:',
      available: 'Possibly available',
      registered: 'Registered',
      restricted: 'Restricted',
      expired: 'Expired',
      expiring: 'Expiring soon',
      available_msg: 'No registration record found. Confirm eligibility with a registrar.',
      restricted_msg: '🔒 WHOIS access restricted by registry',
      status_title: 'Domain Status (EPP)',
      ns_title: 'Nameservers',
      dns_title: 'DNS Records',
      created: 'Created',
      expires: 'Expires',
      updated: 'Updated',
      registrar: 'Registrar',
      organization: 'Organization',
      country: 'Country',
      dnssec: 'DNSSEC',
      server: 'WHOIS Server',
      full_details: 'View full details on Super Whois →',
      official_site: 'Look up on official registry →',
      network_error: 'Network error',
      ttl: 'TTL',
      seconds: 's',
      priority: 'Priority',
      dns_empty: 'No DNS records were returned.',
      dns_partial: 'DNS lookup returned a partial response.',
      ns_hint: 'NS',
      dns_hint: 'DNS',
      permission_error: 'Enter an HTTPS API URL and allow access to that site.',
      address: 'Registrant Address'
    },
    'zh-cn': {
      s_api_url: 'API 基础 URL',
      s_api_hint: '你的 Super Whois API 端点',
      s_api_key: 'API Key（可选）',
      s_key_hint: '留空则使用未认证访问',
      s_lang: '语言',
      s_auto_query: '自动查询当前域名',
      s_auto_query_sub: '打开插件时自动查询',
      s_subdomain_hint: '子域名 → 主域名提示',
      s_subdomain_hint_sub: '子域名时提示查询主域名',
      s_save: '保存设置',
      s_saved: '已保存！',
      lookup: '查询',
      empty: '输入域名、IP 或 ASN\n以查询 WHOIS 信息',
      subdomain_prompt: '检测到子域名：',
      available: '可能可注册',
      registered: '已注册',
      restricted: '访问受限',
      expired: '已过期',
      expiring: '即将过期',
      available_msg: '未找到注册记录；请向注册商确认注册资格。',
      restricted_msg: '🔒 注册局限制了 WHOIS 访问',
      status_title: '域名状态 (EPP)',
      ns_title: '名称服务器 (NS)',
      dns_title: 'DNS 解析记录',
      created: '创建日期',
      expires: '到期日期',
      updated: '更新日期',
      registrar: '注册商',
      organization: '注册组织',
      country: '国家 / 地区',
      dnssec: 'DNSSEC',
      server: 'WHOIS 服务器',
      full_details: '在 Super Whois 查看完整详情 →',
      official_site: '在官方注册局网站查询 →',
      network_error: '网络错误',
      ttl: 'TTL',
      seconds: '秒',
      priority: '优先级',
      dns_empty: '未返回 DNS 记录。',
      dns_partial: 'DNS 查询仅返回部分结果。',
      ns_hint: 'NS',
      dns_hint: 'DNS',
      permission_error: '请填写 HTTPS API 地址，并允许访问该网站。',
      address: '注册人地址'
    },
    'zh-tw': {
      s_api_url: 'API 基礎 URL',
      s_api_hint: '你的 Super Whois API 端點',
      s_api_key: 'API Key（可選）',
      s_key_hint: '留空則使用未認證存取',
      s_lang: '語言',
      s_auto_query: '自動查詢當前域名',
      s_auto_query_sub: '開啟擴充套件時自動查詢',
      s_subdomain_hint: '子域名 → 主域名提示',
      s_subdomain_hint_sub: '子域名時提示查詢主域名',
      s_save: '儲存設定',
      s_saved: '已儲存！',
      lookup: '查詢',
      empty: '輸入域名、IP 或 ASN\n以查詢 WHOIS 資訊',
      subdomain_prompt: '偵測到子域名：',
      available: '可能可註冊',
      registered: '已註冊',
      restricted: '存取受限',
      expired: '已過期',
      expiring: '即將過期',
      available_msg: '未找到註冊記錄；請向註冊商確認註冊資格。',
      restricted_msg: '🔒 註冊局限制了 WHOIS 存取',
      status_title: '網域狀態 (EPP)',
      ns_title: '名稱伺服器 (NS)',
      dns_title: 'DNS 解析記錄',
      created: '建立日期',
      expires: '到期日期',
      updated: '更新日期',
      registrar: '註冊商',
      organization: '註冊組織',
      country: '國家 / 地區',
      dnssec: 'DNSSEC',
      server: 'WHOIS 伺服器',
      full_details: '在 Super Whois 查看完整詳情 →',
      official_site: '在官方註冊局網站查詢 →',
      network_error: '網路錯誤',
      ttl: 'TTL',
      seconds: '秒',
      priority: '優先順序',
      dns_empty: '未回傳 DNS 記錄。',
      dns_partial: 'DNS 查詢僅回傳部分結果。',
      ns_hint: 'NS',
      dns_hint: 'DNS',
      permission_error: '請填寫 HTTPS API 位址，並允許存取該網站。',
      address: '註冊人地址'
    },
  };

  // ── EPP Status Dictionary ────────────────────────────────────────────
  // Maps normalized lowercase alphanumeric EPP status keys to semantic styles & localized labels
  const EPP_MAP = {
    ok: {
      type: 'ok',
      en: 'Active (OK)',
      'zh-cn': '正常 (OK)',
      'zh-tw': '正常 (OK)'
    },
    active: {
      type: 'ok',
      en: 'Active',
      'zh-cn': '正常活跃',
      'zh-tw': '正常活躍'
    },
    clientdeleteprohibited: {
      type: 'shield',
      en: 'Client Delete Prohibited',
      'zh-cn': '注册商禁止删除',
      'zh-tw': '註冊商禁止刪除'
    },
    clienttransferprohibited: {
      type: 'shield',
      en: 'Client Transfer Prohibited',
      'zh-cn': '注册商禁止转移',
      'zh-tw': '註冊商禁止轉移'
    },
    clientupdateprohibited: {
      type: 'shield',
      en: 'Client Update Prohibited',
      'zh-cn': '注册商禁止更新',
      'zh-tw': '註冊商禁止更新'
    },
    clientrenewprohibited: {
      type: 'shield',
      en: 'Client Renew Prohibited',
      'zh-cn': '注册商禁止续费',
      'zh-tw': '註冊商禁止續費'
    },
    serverdeleteprohibited: {
      type: 'shield',
      en: 'Server Delete Prohibited',
      'zh-cn': '注册局禁止删除',
      'zh-tw': '註冊局禁止刪除'
    },
    servertransferprohibited: {
      type: 'shield',
      en: 'Server Transfer Prohibited',
      'zh-cn': '注册局禁止转移',
      'zh-tw': '註冊局禁止轉移'
    },
    serverupdateprohibited: {
      type: 'shield',
      en: 'Server Update Prohibited',
      'zh-cn': '注册局禁止更新',
      'zh-tw': '註冊局禁止更新'
    },
    serverrenewprohibited: {
      type: 'shield',
      en: 'Server Renew Prohibited',
      'zh-cn': '注册局禁止续费',
      'zh-tw': '註冊局禁止續費'
    },
    clienthold: {
      type: 'danger',
      en: 'Client Hold (Suspended)',
      'zh-cn': '注册商暂停解析 (Client Hold)',
      'zh-tw': '註冊商暫停解析 (Client Hold)'
    },
    serverhold: {
      type: 'danger',
      en: 'Server Hold (Suspended)',
      'zh-cn': '注册局暂停解析 (Server Hold)',
      'zh-tw': '註冊局暫停解析 (Server Hold)'
    },
    redemptionperiod: {
      type: 'danger',
      en: 'Redemption Period',
      'zh-cn': '高价赎回期',
      'zh-tw': '高價贖回期'
    },
    pendingdelete: {
      type: 'danger',
      en: 'Pending Delete',
      'zh-cn': '等待删除',
      'zh-tw': '等待刪除'
    },
    pendingtransfer: {
      type: 'warn',
      en: 'Pending Transfer',
      'zh-cn': '转移处理中',
      'zh-tw': '轉移處理中'
    },
    pendingcreate: {
      type: 'warn',
      en: 'Pending Create',
      'zh-cn': '创建处理中',
      'zh-tw': '建立處理中'
    },
    pendingupdate: {
      type: 'warn',
      en: 'Pending Update',
      'zh-cn': '更新处理中',
      'zh-tw': '更新處理中'
    },
    pendingrenew: {
      type: 'warn',
      en: 'Pending Renew',
      'zh-cn': '续费处理中',
      'zh-tw': '續費處理中'
    },
    pendingrestore: {
      type: 'warn',
      en: 'Pending Restore',
      'zh-cn': '恢复处理中',
      'zh-tw': '恢復處理中'
    },
    addperiod: {
      type: 'neutral',
      en: 'Add Grace Period',
      'zh-cn': '新注宽限期',
      'zh-tw': '新註寬限期'
    },
    autorenewperiod: {
      type: 'neutral',
      en: 'Auto-Renew Grace Period',
      'zh-cn': '自动续费宽限期',
      'zh-tw': '自動續費寬限期'
    },
    renewperiod: {
      type: 'neutral',
      en: 'Renew Grace Period',
      'zh-cn': '续费宽限期',
      'zh-tw': '續費寬限期'
    },
    transferperiod: {
      type: 'neutral',
      en: 'Transfer Grace Period',
      'zh-cn': '转移宽限期',
      'zh-tw': '轉移寬限期'
    },
    inactive: {
      type: 'warn',
      en: 'Inactive (No NS)',
      'zh-cn': '未激活 (无 NS)',
      'zh-tw': '未啟用 (無 NS)'
    }
  };

  let currentLang = 'en';
  let lastLookup = null;

  function T(key) {
    return (LANGS[currentLang] || LANGS.en)[key] || LANGS.en[key] || key;
  }

  function applyLang() {
    document.querySelectorAll('[data-i18n]').forEach(el => {
      el.textContent = T(el.dataset.i18n);
    });
    domainInput.placeholder = currentLang.startsWith('zh') ? '例如: google.com' : 'google.com';
    const emptyText = document.getElementById('empty-text');
    if (emptyText) {
      emptyText.innerHTML = T('empty').replace('\n', '<br>');
    } else if (lastLookup) {
      renderResult(lastLookup.json, lastLookup.query);
    }
    document.documentElement.lang = currentLang;
    langSelector.querySelectorAll('.lang-btn').forEach(btn => {
      btn.classList.toggle('active', btn.dataset.lang === currentLang);
    });
  }

  // ── Parse & Normalize EPP Status ─────────────────────────────────────
  function parseEppStatus(rawStatus) {
    // Strip trailing URLs like https://icann.org/epp#clientTransferProhibited and parentheses
    const cleaned = String(rawStatus || '')
      .replace(/\s*\(?https?:\/\/\S+\)?/gi, '')
      .replace(/\s*\(https?:\/\/[^)]*\)/gi, '')
      .trim();
    if (!cleaned) return null;

    // Normalize key: remove spaces, underscores, hyphens, and lowercase
    const normKey = cleaned.toLowerCase().replace(/[\s_-]+/g, '');
    const matched = EPP_MAP[normKey];

    if (matched) {
      return {
        key: normKey,
        raw: cleaned,
        label: matched[currentLang] || matched.en,
        type: matched.type
      };
    }

    // Fallback heuristic if status string isn't in dictionary
    let fallbackType = 'neutral';
    if (normKey.includes('prohibited') || normKey.includes('lock')) fallbackType = 'shield';
    else if (normKey.includes('hold') || normKey.includes('delete') || normKey.includes('redemption')) fallbackType = 'danger';
    else if (normKey.includes('pending')) fallbackType = 'warn';
    else if (normKey === 'ok' || normKey.includes('active')) fallbackType = 'ok';

    // Format camelCase or space-separated fallback nicely
    const readable = cleaned
      .replace(/([a-z])([A-Z])/g, '$1 $2')
      .replace(/\b\w/g, c => c.toUpperCase());

    return {
      key: normKey,
      raw: cleaned,
      label: readable,
      type: fallbackType
    };
  }

  // ── Settings ────────────────────────────────────────────────────────
  saveBtn.addEventListener('click', async () => {
    let endpoint;
    try {
      endpoint = new URL(apiUrlInput.value.trim());
      if (endpoint.username || endpoint.password || endpoint.search || endpoint.hash) throw new Error('url');
      if (endpoint.protocol !== 'https:' && !(endpoint.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(endpoint.hostname))) throw new Error('url');
      const granted = await chrome.permissions.request({ origins: [endpoint.origin + '/*'] });
      if (!granted) throw new Error('permission');
    } catch (error) {
      saveBtn.textContent = T('permission_error');
      return;
    }
    const cleanUrl = endpoint.href.replace(/\/+$/, '');
    apiUrlInput.value = cleanUrl;
    chrome.storage.local.set({
      apiUrl: cleanUrl,
      apiKey: apiKeyInput.value.trim(),
      lang: currentLang,
      autoQuery: autoQueryToggle.checked,
      subdomainHint: subdomainToggle.checked,
    }, () => {
      saveBtn.textContent = T('s_saved');
      setTimeout(() => {
        saveBtn.textContent = T('s_save');
        settingsPanel.classList.remove('open');
        settingsToggle.classList.remove('active');
      }, 900);
    });
  });

  settingsToggle.addEventListener('click', () => {
    const isOpen = settingsPanel.classList.toggle('open');
    settingsToggle.classList.toggle('active', isOpen);
  });

  langSelector.addEventListener('click', (e) => {
    const btn = e.target.closest('.lang-btn');
    if (!btn) return;
    currentLang = btn.dataset.lang;
    applyLang();
  });

  dismissSubdomain.addEventListener('click', () => {
    subdomainHint.style.display = 'none';
  });

  apexLink.addEventListener('click', (e) => {
    e.preventDefault();
    domainInput.value = apexLink.textContent;
    subdomainHint.style.display = 'none';
    doLookup();
  });

  // ── Lookup ──────────────────────────────────────────────────────────
  function sanitize(q) {
    let host = q.trim().replace(/\s+/g, '');
    if (/^https?:\/\//i.test(host)) {
      try { return new URL(host).hostname.replace(/^\[|\]$/g, '').replace(/\.$/, ''); } catch (_) { return ''; }
    }
    host = host.split('/')[0].replace(/\.$/, '');
    if (/^\[[a-f\d:]+\](?::\d+)?$/i.test(host)) return host.slice(1, host.indexOf(']'));
    return host.split(':').length > 2 ? host : host.replace(/:\d+$/, '');
  }

  async function doLookup() {
    const raw = sanitize(domainInput.value);
    if (!raw) return;

    const data = await chrome.storage.local.get(['apiUrl', 'apiKey']);
    const base = (data.apiUrl || '').trim().replace(/\/+$/, '');
    if (!base) {
      settingsPanel.classList.add('open');
      settingsToggle.classList.add('active');
      resultArea.innerHTML = '<div class="error-msg">' + esc(T('permission_error')) + '</div>';
      return;
    }

    lookupBtn.disabled = true;
    lookupBtn.textContent = '…';
    resultArea.innerHTML = '<div class="loading"><div class="spinner"></div></div>';
    subdomainHint.style.display = 'none';

    try {
      const key = data.apiKey || '';
      const url = base + '?q=' + encodeURIComponent(raw) + '&dns=true&raw=false';
      const resp = await fetch(url, {
        headers: key ? { Authorization: 'Bearer ' + key } : {},
        signal: AbortSignal.timeout(30000),
        cache: 'no-store'
      });
      const json = await resp.json();

      // Subdomain hint
      const settings = await chrome.storage.local.get(['subdomainHint']);
      if (settings.subdomainHint !== false) {
        const apex = json.is_subdomain ? json.lookup_domain : null;
        if (apex && apex !== raw.toLowerCase()) {
          subdomainText.textContent = T('subdomain_prompt') + ' ' + raw;
          apexLink.textContent = apex;
          subdomainHint.style.display = 'flex';
        }
      }

      renderResult(json, raw);
    } catch (e) {
      resultArea.innerHTML = '<div class="error-msg">' + T('network_error') + ': ' + esc(e.message) + '</div>';
    } finally {
      lookupBtn.disabled = false;
      lookupBtn.textContent = T('lookup');
    }
  }

  lookupBtn.addEventListener('click', doLookup);
  domainInput.addEventListener('keydown', (e) => {
    if (e.key === 'Enter') doLookup();
  });

  // ── Render ──────────────────────────────────────────────────────────
  function esc(s) {
    const d = document.createElement('div');
    d.textContent = String(s ?? '');
    return d.innerHTML.replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function renderResult(json, query) {
    lastLookup = { json, query };
    if (json.error && !json.status) {
      resultArea.innerHTML = '<div class="error-msg">' + esc(json.error) + '</div>';
      return;
    }

    const status = json.status || 'error';
    const data   = json.data || {};
    const dns    = json.dns_records || {};
    const server = json.whois_server || '';
    const method = json.query_method || '';
    const ms     = json.query_ms || 0;

    let html = '';

    // Hero Card
    html += '<div class="hero-card">';
    html += '<div class="hero-top"><div class="domain-title-wrap">';
    html += '<div class="domain-name">' + esc((json.lookup_domain || query || '').toUpperCase()) + '</div>';
    if (json.unicode_domain) {
      html += '<span class="domain-unicode">' + esc(json.unicode_domain) + '</span>';
    }
    html += '</div></div>';

    html += '<div class="hero-badges">';
    if (status === 'available') {
      html += '<span class="badge badge-available">✓ ' + T('available') + '</span>';
    } else if (status === 'registered' || status === 'found') {
      html += '<span class="badge badge-registered">● ' + T('registered') + '</span>';
      if (data.expiration_date) {
        const exp = new Date(data.expiration_date);
        const now = new Date();
        const daysLeft = Math.floor((exp - now) / 86400000);
        if (daysLeft < 0) {
          html += '<span class="badge badge-expired">⚠ ' + T('expired') + '</span>';
        } else if (daysLeft < 60) {
          html += '<span class="badge badge-expiring">⏳ ' + T('expiring') + ' (' + daysLeft + 'd)</span>';
        }
      }
    } else if (status === 'restricted') {
      html += '<span class="badge badge-expiring">🔒 ' + T('restricted') + '</span>';
    } else {
      html += '<span class="badge badge-registered">' + esc(status) + '</span>';
    }
    if (method || ms) {
      html += '<span class="badge-method">' + esc(method ? method.toUpperCase() : 'WHOIS') + ' · ' + ms + 'ms</span>';
    }
    html += '</div></div>';

    // Content by status
    if (status === 'available') {
      html += '<div class="state-banner available">' + T('available_msg') + '</div>';
    } else if (status === 'restricted') {
      html += '<div class="state-banner restricted">' + T('restricted_msg') + '</div>';
      if (typeof json.web_lookup_url === 'string' && /^https?:\/\//i.test(json.web_lookup_url)) {
        html += '<a class="footer-link" href="' + esc(json.web_lookup_url) + '" target="_blank">' + T('official_site') + '</a>';
      }
    } else if (status === 'registered' || status === 'found') {
      html += '<div class="info-grid">';
      if (data.creation_date)      html += cell(T('created'), fmtDate(data.creation_date));
      if (data.expiration_date)    html += cell(T('expires'), fmtDate(data.expiration_date));
      if (data.updated_date)       html += cell(T('updated'), fmtDate(data.updated_date));
      if (data.dnssec)             html += cell(T('dnssec'), data.dnssec);
      if (data.registrar)          html += cell(T('registrar'), data.registrar, true);
      if (data.registrant_org)     html += cell(T('organization'), data.registrant_org);
      if (data.registrant_country) html += cell(T('country'), data.registrant_country);
      const address = [data.registrant_address, data.registrant_city, data.registrant_region, data.registrant_postal_code].filter(Boolean).join(', ');
      if (address)                 html += cell(T('address'), address, true);
      if (server)                  html += cell(T('server'), server, true);
      html += '</div>';

      // Semantic EPP Status Pills
      const rawStatuses = Array.isArray(data.status) ? data.status : [];
      const parsedStatuses = [];
      const seenKeys = new Set();

      rawStatuses.forEach(s => {
        const item = parseEppStatus(s);
        if (item && !seenKeys.has(item.key)) {
          seenKeys.add(item.key);
          parsedStatuses.push(item);
        }
      });

      if (parsedStatuses.length > 0) {
        html += '<section class="record-panel">';
        html += '<div class="record-heading"><h2>' + T('status_title') + '</h2><span class="record-count">' + parsedStatuses.length + '</span></div>';
        html += '<div class="epp-pill-grid">';
        parsedStatuses.forEach(st => {
          html += '<span class="epp-pill epp-' + st.type + '" title="' + esc(st.raw) + '">';
          html += '<span class="epp-dot"></span>' + esc(st.label);
          html += '</span>';
        });
        html += '</div></section>';
      }

      // Nameservers
      const ns = [...new Set(data.nameservers || [])];
      if (ns.length > 0) {
        html += '<section class="record-panel"><div class="record-heading"><h2>' + T('ns_title') + '</h2><span class="record-count">' + ns.length + '</span></div><ul class="record-list">';
        ns.forEach(n => {
          html += '<li class="record-row"><code class="record-value">' + esc(n) + '</code><span class="record-meta">' + T('ns_hint') + '</span></li>';
        });
        html += '</ul></section>';
      }
    }

    if (status === 'error' && json.error) {
      html += '<div class="error-msg">' + esc(json.error) + '</div>';
    }
    if (!json.query_type || json.query_type === 'domain') {
      html += renderDNS(dns);
    }

    // Full details link
    const siteBase = (apiUrlInput.value || '').trim().replace(/api\.php$/, '').replace(/\/+$/, '');
    if (siteBase) {
      const lang = currentLang;
      html += '<a class="footer-link" href="' + esc(siteBase + '/index.php?lang=' + lang + '&query=' + encodeURIComponent(query)) + '" target="_blank">' + T('full_details') + '</a>';
    }

    resultArea.innerHTML = html;
  }

  function renderDNS(dns) {
    const types = ['A', 'AAAA', 'CNAME', 'MX', 'TXT', 'NS'];
    const records = dns && dns.records && typeof dns.records === 'object' ? dns.records : {};
    const count = types.reduce((total, type) => total + (Array.isArray(records[type]) ? records[type].length : 0), 0);
    let html = '<section class="record-panel"><div class="record-heading"><h2>' + T('dns_title') + '</h2><span class="record-count">' + count + '</span></div>';
    types.forEach(type => {
      const rows = Array.isArray(records[type]) ? records[type] : [];
      if (!rows.length) return;
      html += '<details class="record-group"' + (type === 'TXT' ? '' : ' open') + '><summary><span class="record-type">' + type + '</span><span>' + rows.length + '</span></summary><ul class="record-list">';
      rows.forEach(record => {
        const value = record.ip ?? record.ipv6 ?? record.host ?? record.target ?? record.txt ?? '';
        const meta = [];
        if (type === 'MX' && record.priority != null) meta.push(T('priority') + ' ' + String(record.priority));
        if (record.ttl != null) meta.push(String(record.ttl) + T('seconds'));
        html += '<li class="record-row"><code class="record-value">' + esc(String(value)) + '</code><div class="record-meta">' + meta.map(esc).join(' · ') + '</div></li>';
      });
      html += '</ul></details>';
    });
    if (!count) html += '<p class="record-empty">' + T('dns_empty') + '</p>';
    if (Array.isArray(dns.errors) && dns.errors.length && count) html += '<p class="record-empty">' + T('dns_partial') + '</p>';
    return html + '</section>';
  }

  function cell(label, value, full = false) {
    return '<div class="info-cell' + (full ? ' full' : '') + '"><div class="info-label">' + esc(label) + '</div><div class="info-value">' + esc(value) + '</div></div>';
  }

  function fmtDate(s) {
    if (!s) return '';
    const d = new Date(s);
    if (isNaN(d)) return s;
    return d.toISOString().slice(0, 10);
  }

  // ── Init ────────────────────────────────────────────────────────────
  chrome.storage.local.get(['apiUrl', 'apiKey', 'lang', 'autoQuery', 'subdomainHint'], (data) => {
    const savedUrl = (data.apiUrl || '').trim();
    apiUrlInput.value = savedUrl;
    apiKeyInput.value = data.apiKey || '';
    currentLang = data.lang || detectBrowserLang();
    autoQueryToggle.checked = data.autoQuery !== false;
    subdomainToggle.checked = data.subdomainHint !== false;
    applyLang();

    if (!savedUrl) {
      settingsPanel.classList.add('open');
      settingsToggle.classList.add('active');
      return;
    }

    if (data.autoQuery !== false) {
      chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
        if (!tabs || !tabs[0] || !tabs[0].url) return;
        try {
          const u = new URL(tabs[0].url);
          if (!u.hostname || u.hostname === 'localhost' || !u.hostname.includes('.')) return;
          domainInput.value = u.hostname;
          doLookup();
        } catch (e) {}
      });
    }
  });

  function detectBrowserLang() {
    const lang = navigator.language || 'en';
    if (lang.startsWith('zh')) {
      return (lang.includes('TW') || lang.includes('HK') || lang.includes('Hant')) ? 'zh-tw' : 'zh-cn';
    }
    return 'en';
  }
})();