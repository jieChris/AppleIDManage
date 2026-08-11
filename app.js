(() => {
  'use strict';

  const STORAGE_KEY = 'apple-id-vault-records';
  const AUTH_STORAGE_KEY = 'apple-id-vault-auth';
  const VALID_CODE_STATUSES = new Set(['idle', 'loading', 'found', 'empty', 'blocked']);
  const CORE_FIELDS = ['account', 'password', 'birthDate', 'country'];
  const CODE_LABEL_RE = /(?:验证码|校验码|动态码|安全码|短信码|一次性密码|otp\b|one[-\s]?time(?:\s+password)?|verification(?:\s+code)?|security\s+code|passcode|\bcode\b)/iu;

  function asText(value) {
    return value == null ? '' : String(value);
  }

  function clean(value) {
    return asText(value).trim().replace(/\s+/g, ' ');
  }

  function makeId() {
    try {
      if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    } catch {
      // Fall through to the local fallback when randomUUID is unavailable.
    }
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  function splitAccountFields(line) {
    const source = asText(line).trim();
    const strategies = [
      /\s*-{2,}\s*/,
      /\t+/,
      /\s{2,}/,
      /\s+-\s+/,
    ];

    for (const strategy of strategies) {
      const fields = source.split(strategy).map(clean).filter((field, index, all) => field || index === all.length - 1);
      if (fields.length >= 7) return fields;
    }

    const tokens = source.split(/\s+/).filter(Boolean);
    if (tokens.length >= 7) {
      return [
        tokens[0],
        tokens[1],
        tokens[2],
        tokens[3],
        tokens[4],
        tokens[5],
        tokens.slice(6).join(' '),
      ];
    }

    return source.split(/\s+-\s+/).map(clean);
  }

  function parseAccountLine(line) {
    const fields = splitAccountFields(line);
    if (fields.length < 7) {
      return { error: `需要 7 个字段，当前识别到 ${fields.length} 个` };
    }

    const [account, password, question1, question2, question3, birthDate, ...countryParts] = fields;
    if (!account) return { error: '账号不能为空' };

    return {
      account,
      password,
      questions: [question1, question2, question3],
      birthDate,
      country: countryParts.join(' ').trim(),
    };
  }

  function parseContactLine(line) {
    if (!asText(line).includes('|')) return null;

    const [phonePart, ...urlParts] = asText(line).split('|');
    const phone = clean(phonePart);
    const codeUrl = urlParts.join('|').trim();
    const digits = phone.replace(/\D/g, '');

    if (digits.length < 7 || digits.length > 15) {
      return { error: '手机号格式不完整' };
    }

    try {
      const parsedUrl = new URL(codeUrl);
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) throw new Error('unsupported protocol');
    } catch {
      return { error: '取码链接必须是 http 或 https 地址' };
    }

    return { phone, codeUrl };
  }

  function parseRemarkLine(line) {
    const match = asText(line).match(/^备注(?:\||：|:)\s*(.*)$/u);
    return match ? { remark: clean(match[1]) } : null;
  }

  function createParsedRecord(accountData) {
    return {
      id: makeId(),
      ...accountData,
      remark: '',
      phone: '',
      codeUrl: '',
      hasContact: false,
      smsCode: '',
      codeStatus: 'idle',
      codeError: '',
      codeCheckedAt: '',
      updatedAt: new Date().toISOString(),
    };
  }

  function parseImport(text) {
    const lines = asText(text).split(/\r?\n/);
    const records = [];
    const errors = [];

    lines.forEach((rawLine, index) => {
      const line = rawLine.trim();
      if (!line) return;

      const remark = parseRemarkLine(line);
      if (remark) {
        if (!records.length) {
          errors.push({ line: index + 1, raw: line, message: '备注行需要放在账号行后面' });
          return;
        }
        records[records.length - 1].remark = remark.remark;
        return;
      }

      if (line.includes('|')) {
        const contact = parseContactLine(line);
        if (contact?.error) {
          errors.push({ line: index + 1, raw: line, message: contact.error });
          return;
        }
        if (!contact || !records.length) {
          errors.push({ line: index + 1, raw: line, message: '手机号行需要放在账号行后面' });
          return;
        }

        const record = records[records.length - 1];
        if (record.hasContact) {
          errors.push({ line: index + 1, raw: line, message: '同一账号只能绑定一行手机号和取码链接' });
          return;
        }

        Object.assign(record, contact, { hasContact: true });
        return;
      }

      const account = parseAccountLine(line);
      if (account.error) {
        errors.push({ line: index + 1, raw: line, message: account.error });
        return;
      }
      records.push(createParsedRecord(account));
    });

    return { records, errors };
  }

  function hasCodeLabel(beforeText) {
    return CODE_LABEL_RE.test(asText(beforeText).slice(-48));
  }

  function isTemporalCandidate(source, index, value, labeled) {
    if (labeled) return false;

    const beforeChar = source[index - 1] || '';
    const afterChar = source[index + 6] || '';
    if (/[\d:/-]/.test(beforeChar) || /[\d:/-]/.test(afterChar)) return true;

    const context = source.slice(Math.max(0, index - 32), Math.min(source.length, index + 38));
    const hasTemporalLabel = /时间|日期|timestamp|\btime\b|\bdate\b|created|updated|expires?|utc|gmt|出生|年|月|日/iu.test(context);
    if (hasTemporalLabel) return true;

    const hours = Number(value.slice(0, 2));
    const minutes = Number(value.slice(2, 4));
    const seconds = Number(value.slice(4, 6));
    const looksLikeTime = hours <= 23 && minutes <= 59 && seconds <= 59;
    if (looksLikeTime && /[T:：]/.test(context)) return true;

    const year = Number(value.slice(0, 4));
    const month = Number(value.slice(4, 6));
    return year >= 1900 && year <= 2100 && month >= 1 && month <= 12 && /[-/]/.test(context);
  }

  function extractSixDigitCode(text) {
    const source = asText(text).replace(/\r?\n/g, ' ');
    const candidates = [];
    const matcher = /(^|[^\d])(\d{6})(?!\d)/g;
    let match;

    while ((match = matcher.exec(source))) {
      const index = match.index + match[1].length;
      const value = match[2];
      const labeled = hasCodeLabel(source.slice(Math.max(0, index - 48), index));
      if (!isTemporalCandidate(source, index, value, labeled)) {
        candidates.push({ value, labeled });
      }
    }

    return candidates.find((candidate) => candidate.labeled)?.value || candidates[0]?.value || '';
  }

  function normalizeRecord(record) {
    if (!record || typeof record !== 'object') return null;
    const questions = Array.isArray(record.questions) ? record.questions : [];
    const codeStatus = VALID_CODE_STATUSES.has(record.codeStatus) ? record.codeStatus : 'idle';

    return {
      id: clean(record.id) || makeId(),
      account: clean(record.account),
      password: asText(record.password),
      questions: [0, 1, 2].map((index) => clean(questions[index])),
      birthDate: clean(record.birthDate),
      country: clean(record.country),
      remark: clean(record.remark),
      phone: clean(record.phone),
      codeUrl: clean(record.codeUrl),
      smsCode: /^\d{6}$/.test(asText(record.smsCode)) ? asText(record.smsCode) : '',
      codeStatus,
      codeError: clean(record.codeError),
      codeCheckedAt: clean(record.codeCheckedAt),
      updatedAt: clean(record.updatedAt) || new Date().toISOString(),
    };
  }

  function loadRecords() {
    if (typeof localStorage === 'undefined') return [];
    try {
      const parsed = JSON.parse(localStorage.getItem(STORAGE_KEY) || '[]');
      return Array.isArray(parsed) ? parsed.map(normalizeRecord).filter(Boolean) : [];
    } catch {
      return [];
    }
  }

  function saveRecords(records) {
    if (typeof localStorage === 'undefined') return false;
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(records.map(normalizeRecord).filter(Boolean)));
      return true;
    } catch {
      return false;
    }
  }

  function mergeRecords(existing, parsed) {
    const result = existing.map(normalizeRecord).filter(Boolean);
    const indexByAccount = new Map(result.map((record, index) => [record.account, index]));
    let duplicateCount = 0;

    parsed.forEach((candidate) => {
      const normalized = normalizeRecord(candidate);
      if (!normalized || !normalized.account) return;

      const existingIndex = indexByAccount.get(normalized.account);
      if (existingIndex === undefined) {
        result.push(normalized);
        indexByAccount.set(normalized.account, result.length - 1);
        return;
      }

      duplicateCount += 1;
      const previous = result[existingIndex];
      const hasContact = candidate.hasContact === true;
      const codeChanged = hasContact && normalized.codeUrl !== previous.codeUrl;
      const next = {
        ...previous,
        ...normalized,
        id: previous.id,
        remark: previous.remark,
        updatedAt: new Date().toISOString(),
      };

      if (!hasContact) {
        next.phone = previous.phone;
        next.codeUrl = previous.codeUrl;
        next.smsCode = previous.smsCode;
        next.codeStatus = previous.codeStatus;
        next.codeError = previous.codeError;
        next.codeCheckedAt = previous.codeCheckedAt;
      } else if (!codeChanged) {
        next.smsCode = previous.smsCode;
        next.codeStatus = previous.codeStatus;
        next.codeError = previous.codeError;
        next.codeCheckedAt = previous.codeCheckedAt;
      } else {
        next.smsCode = '';
        next.codeStatus = 'idle';
        next.codeError = '';
        next.codeCheckedAt = '';
      }

      result[existingIndex] = next;
    });

    return { records: result, duplicateCount };
  }

  function formatRecordForExport(record) {
    const normalized = normalizeRecord(record);
    if (!normalized?.account) return '';

    const lines = [[
      normalized.account,
      normalized.password,
      ...normalized.questions,
      normalized.birthDate,
      normalized.country,
    ].join('----')];

    if (normalized.phone && normalized.codeUrl) lines.push(`${normalized.phone}|${normalized.codeUrl}`);
    if (normalized.remark) lines.push(`备注|${normalized.remark}`);
    return lines.join('\n');
  }

  function formatExportText(records) {
    return (Array.isArray(records) ? records : [])
      .map(formatRecordForExport)
      .filter(Boolean)
      .join('\n');
  }

  function isIncomplete(record) {
    if (!record) return true;
    const coreValues = [
      record.account,
      record.password,
      ...(record.questions || []),
      record.birthDate,
      record.country,
    ];
    return coreValues.some((value) => !clean(value));
  }

  function escapeHtml(value) {
    return asText(value).replace(/[&<>'"]/g, (character) => ({
      '&': '&amp;',
      '<': '&lt;',
      '>': '&gt;',
      "'": '&#39;',
      '"': '&quot;',
    })[character]);
  }

  function formatCheckedAt(value) {
    if (!value) return '';
    const date = new Date(value);
    if (Number.isNaN(date.getTime())) return '';
    return new Intl.DateTimeFormat('zh-CN', {
      month: 'numeric',
      day: 'numeric',
      hour: '2-digit',
      minute: '2-digit',
    }).format(date);
  }

  function getCodeProxyUrl(url, pageHref = typeof location === 'undefined' ? '' : location.href) {
    const source = asText(url);
    if (!source || !pageHref) return '';
    try {
      const proxy = new URL('api/fetch-code', pageHref);
      proxy.searchParams.set('url', source);
      return proxy.href;
    } catch {
      return '';
    }
  }

  function getCodeRequestUrls(
    url,
    pageProtocol = typeof location === 'undefined' ? 'https:' : location.protocol,
    pageHref = typeof location === 'undefined' ? '' : location.href,
  ) {
    const source = asText(url);
    try {
      const parsed = new URL(source);
      if (!['http:', 'https:'].includes(parsed.protocol)) return [source];

      const requestUrls = [];
      const proxyUrl = getCodeProxyUrl(source, pageHref);
      if (proxyUrl) requestUrls.push(proxyUrl);

      if (pageProtocol === 'https:' && parsed.protocol === 'http:') {
        parsed.protocol = 'https:';
        requestUrls.push(parsed.href);
      }
      requestUrls.push(source);
      return [...new Set(requestUrls)];
    } catch {
      return [source];
    }
  }

  function getCodeFailureMessage(url, pageProtocol = typeof location === 'undefined' ? 'https:' : location.protocol) {
    try {
      const parsed = new URL(url);
      if (pageProtocol === 'https:' && parsed.protocol === 'http:') {
        return '取码链接是 HTTP，浏览器直读会被拦截，本站代理也未能读取';
      }
    } catch {
      return '取码链接格式无效';
    }
    return '取码代理无法读取目标链接';
  }

  function getVaultApiUrl(path, pageHref = typeof location === 'undefined' ? '' : location.href) {
    if (!pageHref) return '';
    try {
      return new URL(`api/vault/${asText(path).replace(/^\/+/, '')}`, pageHref).href;
    } catch {
      return '';
    }
  }

  function normalizeServerState(payload) {
    const records = Array.isArray(payload?.records)
      ? payload.records.map(normalizeRecord).filter((record) => record?.account)
      : [];
    const deleted = {};
    if (payload?.deleted && typeof payload.deleted === 'object') {
      Object.entries(payload.deleted).forEach(([account, timestamp]) => {
        if (account && timestamp) deleted[account] = clean(timestamp);
      });
    }
    return {
      revision: Number.isFinite(Number(payload?.revision)) ? Number(payload.revision) : 0,
      records,
      deleted,
      clearAt: clean(payload?.clearAt),
    };
  }

  async function fetchJsonWithTimeout(url, options = {}) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = window.setTimeout(() => controller?.abort(), 8000);
    try {
      const response = await fetch(url, {
        ...options,
        cache: 'no-store',
        credentials: 'same-origin',
        headers: {
          Accept: 'application/json',
          ...(options.headers || {}),
        },
        signal: controller?.signal,
      });
      const raw = await response.text();
      let payload = null;
      try {
        payload = raw ? JSON.parse(raw) : null;
      } catch {
        payload = null;
      }
      if (!response.ok) {
        const error = new Error(payload?.error || `HTTP ${response.status}`);
        error.status = response.status;
        throw error;
      }
      return payload;
    } finally {
      window.clearTimeout(timer);
    }
  }

  function runSelfCheck() {
    const dash = parseImport(
      'a@example.com----pass----Q1----Q2----Q3----1984/2/25----美国\n+18178668072|https://example.com/code',
    );
    console.assert(dash.records[0]?.account === 'a@example.com');
    console.assert(dash.records[0]?.phone === '+18178668072');
    console.assert(dash.records[0]?.codeUrl === 'https://example.com/code');

    const spaced = parseImport('b@example.com  pass  Q one  Q two  Q three  1984/2/25  美国');
    console.assert(spaced.records.length === 1);
    console.assert(parseImport('c@example.com - pass - Q1 - Q2 - Q3 - 1984/2/25 - 美国').records.length === 1);

    console.assert(extractSixDigitCode('验证码：483921') === '483921');
    console.assert(extractSixDigitCode('时间 12:34:56，日期 2026-08-11') === '');
    console.assert(extractSixDigitCode('时间 123456') === '');
    console.assert(extractSixDigitCode('request id 1234567890') === '');
    const proxyRequests = getCodeRequestUrls('http://sms.test/code', 'https:', 'https://vault.test/appleid/');
    console.assert(proxyRequests[0].startsWith('https://vault.test/appleid/api/fetch-code?url='));
    console.assert(decodeURIComponent(proxyRequests[0].split('url=')[1]) === 'http://sms.test/code');
    console.assert(getCodeFailureMessage('http://sms.test/code', 'https:').includes('代理'));
    console.assert(getCodeFailureMessage('https://sms.test/code', 'https:').includes('代理'));
    console.assert(dash.records[0]?.remark === '');
    console.assert(normalizeRecord({ account: 'a@example.com', remark: '个人备注' }).remark === '个人备注');
    const exported = formatExportText([{
      account: 'a@example.com',
      password: 'secret',
      questions: ['Q1', 'Q2', 'Q3'],
      birthDate: '1984/2/25',
      country: '美国',
      phone: '+18178668072',
      codeUrl: 'https://example.com/code',
      remark: '长期使用',
    }]);
    console.assert(exported === 'a@example.com----secret----Q1----Q2----Q3----1984/2/25----美国\n+18178668072|https://example.com/code\n备注|长期使用');
    console.assert(parseImport(exported).records[0]?.remark === '长期使用');
    console.log('parser self-check: ok');
  }

  const api = {
    parseImport,
    parseAccountLine,
    parseContactLine,
    formatRecordForExport,
    formatExportText,
    extractSixDigitCode,
    getCodeProxyUrl,
    getCodeRequestUrls,
    isIncomplete,
    loadRecords,
    saveRecords,
    mergeRecords,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  runSelfCheck();

  if (typeof document === 'undefined') return;

  const legacyRecords = loadRecords();

  function readStoredAuthHeader() {
    try {
      return sessionStorage.getItem(AUTH_STORAGE_KEY) || '';
    } catch {
      return '';
    }
  }

  const state = {
    records: [],
    legacyRecords,
    authHeader: readStoredAuthHeader(),
    revision: 0,
    deleted: {},
    clearAt: '',
    filter: 'all',
    query: '',
    revealed: new Set(),
    toastTimer: null,
    remarkTimers: new Map(),
    syncQueue: Promise.resolve(),
    syncStatus: 'loading',
    canWrite: false,
  };

  const elements = {
    importInput: document.querySelector('#importInput'),
    parseButton: document.querySelector('#parseButton'),
    exportAllButton: document.querySelector('#exportAllButton'),
    clearAllButton: document.querySelector('#clearAllButton'),
    syncButton: document.querySelector('#syncButton'),
    syncStatus: document.querySelector('#syncStatus'),
    syncStatusText: document.querySelector('#syncStatusText'),
    searchInput: document.querySelector('#searchInput'),
    importFeedback: document.querySelector('#importFeedback'),
    recordsList: document.querySelector('#recordsList'),
    emptyState: document.querySelector('#emptyState'),
    totalCount: document.querySelector('#totalCount'),
    completeCount: document.querySelector('#completeCount'),
    incompleteCount: document.querySelector('#incompleteCount'),
    confirmDialog: document.querySelector('#confirmDialog'),
    confirmTitle: document.querySelector('#confirmTitle'),
    confirmMessage: document.querySelector('#confirmMessage'),
    authDialog: document.querySelector('#authDialog'),
    authForm: document.querySelector('#authForm'),
    authPassword: document.querySelector('#authPassword'),
    authError: document.querySelector('#authError'),
    authSubmit: document.querySelector('#authSubmit'),
    toast: document.querySelector('#toast'),
  };

  state.confirmAction = null;

  function setAuthHeader(value) {
    state.authHeader = value;
    try {
      if (value) sessionStorage.setItem(AUTH_STORAGE_KEY, value);
      else sessionStorage.removeItem(AUTH_STORAGE_KEY);
    } catch {
      // Private browsing or storage restrictions should not block in-memory login.
    }
  }

  function notify(message, tone = 'info') {
    if (!elements.toast) return;
    window.clearTimeout(state.toastTimer);
    elements.toast.textContent = message;
    elements.toast.dataset.tone = tone;
    elements.toast.classList.add('is-visible');
    state.toastTimer = window.setTimeout(() => elements.toast.classList.remove('is-visible'), 2600);
  }

  function setWriteAvailability() {
    const writable = state.canWrite;
    if (elements.parseButton) elements.parseButton.disabled = !writable;
    if (elements.clearAllButton) elements.clearAllButton.disabled = !writable;
    if (elements.exportAllButton) {
      elements.exportAllButton.disabled = !state.records.length || ['loading', 'syncing', 'auth'].includes(state.syncStatus);
    }
    document.querySelectorAll('[data-write]').forEach((control) => {
      control.disabled = !writable;
    });
  }

  function setSyncStatus(status, message) {
    state.syncStatus = status;
    state.canWrite = status === 'ready';
    const labels = {
      loading: '连接共享库…',
      syncing: '同步中…',
      ready: '已连接 · 共享库',
      auth: '等待门禁登录',
      error: '同步失败 · 只读',
    };
    if (elements.syncStatus) elements.syncStatus.dataset.status = status;
    if (elements.syncStatusText) elements.syncStatusText.textContent = message || labels[status] || status;
    if (elements.syncButton) elements.syncButton.disabled = ['loading', 'syncing', 'auth'].includes(status);
    setWriteAvailability();
  }

  function getRequestHeaders(url, extra = {}) {
    const headers = { ...extra };
    if (!state.authHeader) return headers;
    try {
      if (new URL(url, window.location.href).origin !== window.location.origin) return headers;
    } catch {
      return headers;
    }
    return { Authorization: state.authHeader, ...headers };
  }

  function showAuthDialog(message = '') {
    if (elements.authError) elements.authError.textContent = message;
    if (!elements.authDialog) return;
    if (!elements.authDialog.open) {
      if (elements.authDialog.showModal) elements.authDialog.showModal();
      else elements.authDialog.setAttribute('open', '');
    }
    window.setTimeout(() => elements.authPassword?.focus(), 0);
  }

  function applyServerState(payload) {
    const next = normalizeServerState(payload);
    state.records = next.records;
    state.revision = next.revision;
    state.deleted = next.deleted;
    state.clearAt = next.clearAt;
  }

  function touchRecord(record) {
    const previous = Date.parse(record.updatedAt) || 0;
    const timestamp = Math.max(Date.now(), previous + 1);
    record.updatedAt = new Date(timestamp).toISOString();
    return record.updatedAt;
  }

  function getSyncErrorMessage(error) {
    if (error?.name === 'AbortError') return '共享库请求超时';
    return error?.message || '共享库暂时无法连接';
  }

  async function requestVault(path, options = {}) {
    const url = getVaultApiUrl(path);
    if (!url) throw new Error('共享库地址无效');
    return fetchJsonWithTimeout(url, {
      ...options,
      headers: getRequestHeaders(url, options.headers || {}),
    });
  }

  function syncSnapshot(records, deleted = state.deleted, clearAt = state.clearAt, options = {}) {
    if (!state.canWrite && state.syncStatus !== 'syncing') return Promise.reject(new Error('共享库不可用，当前为只读状态'));
    const { renderResult = true, migrate = false } = options;
    const snapshot = {
      records: records.map(normalizeRecord).filter((record) => record?.account),
      deleted: { ...deleted },
      clearAt,
      migrate,
    };
    const task = state.syncQueue.then(async () => {
      if (!state.canWrite && state.syncStatus !== 'syncing') throw new Error('共享库不可用，当前为只读状态');
      setSyncStatus('syncing');
      try {
        const payload = await requestVault('sync', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(snapshot),
        });
        applyServerState(payload);
        setSyncStatus('ready');
        if (renderResult) render();
        return payload;
      } catch (error) {
        setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
        throw error;
      }
    });
    state.syncQueue = task.catch(() => {});
    return task;
  }

  function clearServerState() {
    if (!state.canWrite) return Promise.reject(new Error('共享库不可用，当前为只读状态'));
    const task = state.syncQueue.then(async () => {
      if (!state.canWrite) throw new Error('共享库不可用，当前为只读状态');
      setSyncStatus('syncing');
      try {
        const payload = await requestVault('clear', { method: 'POST' });
        applyServerState(payload);
        setSyncStatus('ready');
        render();
        return payload;
      } catch (error) {
        setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
        throw error;
      }
    });
    state.syncQueue = task.catch(() => {});
    return task;
  }

  async function loadServerState(initial = false) {
    const fallbackRecords = initial ? [] : state.records;
    setSyncStatus('loading');
    try {
      const payload = await requestVault('state');
      applyServerState(payload);
      setSyncStatus('ready');
      render();

      if (state.legacyRecords.length) {
        await syncSnapshot(state.legacyRecords, state.deleted, state.clearAt, { migrate: true });
        try {
          localStorage.removeItem(STORAGE_KEY);
        } catch {
          // The server copy is already safe if browser storage cannot be cleared.
        }
        state.legacyRecords = [];
        notify('本机旧资料已迁移到共享库', 'success');
      }
    } catch (error) {
      if (error?.status === 401) {
        setAuthHeader('');
        state.records = fallbackRecords;
        setSyncStatus('auth');
        render();
        showAuthDialog('门禁密码不正确，请重试');
        return;
      }
      state.records = fallbackRecords;
      setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
      render();
      notify('共享库暂时不可用，已切换只读模式', 'warning');
    }
  }

  async function handleAuthSubmit(event) {
    event.preventDefault();
    const password = elements.authPassword?.value.trim() || '';
    if (!password) {
      if (elements.authError) elements.authError.textContent = '请输入门禁密码';
      return;
    }

    let encoded;
    try {
      encoded = window.btoa(`vault:${password}`);
    } catch {
      if (elements.authError) elements.authError.textContent = '密码格式无法处理';
      return;
    }

    setAuthHeader(`Basic ${encoded}`);
    if (elements.authSubmit) elements.authSubmit.disabled = true;
    if (elements.authError) elements.authError.textContent = '验证中…';
    await loadServerState(true);
    if (state.syncStatus === 'ready') {
      elements.authPassword.value = '';
      elements.authError.textContent = '';
      if (elements.authDialog?.close) elements.authDialog.close();
      else elements.authDialog?.removeAttribute('open');
    } else {
      setAuthHeader('');
      if (state.syncStatus !== 'auth') setSyncStatus('auth');
      if (elements.authError?.textContent === '验证中…') {
        elements.authError.textContent = '门禁验证失败，请重试';
      }
    }
    if (elements.authSubmit) elements.authSubmit.disabled = false;
  }

  function getFieldValue(record, field) {
    if (field.startsWith('question')) {
      return record.questions[Number(field.slice(-1)) - 1] || '';
    }
    if (field === 'verificationCode') return record.smsCode || '';
    return record[field] || '';
  }

  function renderCopyField(record, field, label, value, options = {}) {
    const { sensitive = false, className = '', emptyText = '未填写' } = options;
    const revealed = state.revealed.has(record.id);
    const visibleValue = sensitive && !revealed && value ? '••••••••' : value || emptyText;
    const disabled = !value;
    return `
      <div class="data-field ${className}">
        <span class="field-label">${escapeHtml(label)}</span>
        <button class="field-value ${sensitive ? 'is-secret' : ''} ${disabled ? 'is-empty' : ''}" type="button"
          data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="${escapeHtml(field)}"
          ${disabled ? 'disabled' : ''} aria-label="复制${escapeHtml(label)}">
          <span>${escapeHtml(visibleValue)}</span>
          ${disabled ? '' : '<span class="copy-hint">复制</span>'}
        </button>
      </div>`;
  }

  function codeStatusMarkup(record) {
    const status = record.codeStatus || 'idle';
    if (!record.codeUrl) {
      return '<span class="code-status is-empty">未绑定取码链接</span>';
    }
    if (status === 'loading') return '<span class="code-status is-loading">读取中…</span>';
    if (status === 'found') {
      return `<button class="code-status is-found" type="button" data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="verificationCode" aria-label="复制验证码">${escapeHtml(record.smsCode)} <span>复制</span></button>`;
    }
    if (status === 'blocked') {
      const isMixedContent = record.codeUrl.startsWith('http:') && location.protocol === 'https:';
      const reason = isMixedContent ? getCodeFailureMessage(record.codeUrl) : (record.codeError || '取码链接未开放 CORS，无法自动读取');
      return `<span class="code-status is-blocked" title="${escapeHtml(reason)}">无法读取</span>`;
    }
    if (status === 'empty') return '<span class="code-status is-empty">无验证码</span>';
    return '<span class="code-status is-loading">等待读取</span>';
  }

  function renderRecord(record) {
    const incomplete = isIncomplete(record);
    const statusLabel = incomplete ? '待检查' : '资料完整';
    const phoneMarkup = record.phone
      ? `<button class="phone-value" type="button" data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="phone" aria-label="复制手机号">${escapeHtml(record.phone)}<span>复制</span></button>`
      : '<span class="muted-value">未绑定手机号</span>';
    const linkMarkup = record.codeUrl
      ? `<a class="link-value" href="${escapeHtml(record.codeUrl)}" target="_blank" rel="noreferrer">打开取码链接 <span>↗</span></a>`
      : '<span class="muted-value">未绑定取码链接</span>';
    const linkCopyMarkup = record.codeUrl
      ? `<button class="link-copy" type="button" data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="codeUrl">复制链接</button>`
      : '';

    return `
      <article class="record-card ${incomplete ? 'is-incomplete' : ''}" data-record-id="${escapeHtml(record.id)}">
        <details class="record-details">
          <summary class="record-summary">
            <h3>${escapeHtml(record.account || '未命名账号')}</h3>
            <span class="record-chevron" aria-hidden="true">⌄</span>
          </summary>
          <div class="record-body">
            <div class="record-head">
              <div class="record-identity">
                <span class="status-pill ${incomplete ? 'is-warning' : 'is-ready'}"><i></i>${statusLabel}</span>
              </div>
              <div class="record-actions">
                <button class="icon-button" type="button" data-action="toggle-password" data-record-id="${escapeHtml(record.id)}" aria-label="${state.revealed.has(record.id) ? '隐藏密码' : '显示密码'}">${state.revealed.has(record.id) ? '隐藏' : '显密'}</button>
                <button class="icon-button is-danger" type="button" data-action="delete" data-record-id="${escapeHtml(record.id)}" data-write aria-label="删除账号" ${state.canWrite ? '' : 'disabled'}>删除</button>
              </div>
            </div>

            <div class="record-grid">
              ${renderCopyField(record, 'account', '账号', record.account, { className: 'field-account' })}
              ${renderCopyField(record, 'password', '密码', record.password, { sensitive: true, className: 'field-password' })}
              ${renderCopyField(record, 'question1', '密保问题 01', record.questions[0])}
              ${renderCopyField(record, 'question2', '密保问题 02', record.questions[1])}
              ${renderCopyField(record, 'question3', '密保问题 03', record.questions[2])}
              ${renderCopyField(record, 'birthDate', '出生日期', record.birthDate)}
              ${renderCopyField(record, 'country', '国家', record.country)}
              <div class="data-field field-phone">
                <span class="field-label">手机号</span>
                ${phoneMarkup}
              </div>
              <div class="data-field field-remark">
                <label class="field-label" for="remark-${escapeHtml(record.id)}">备注</label>
                <input class="remark-input" id="remark-${escapeHtml(record.id)}" type="text" data-action="update-remark" data-record-id="${escapeHtml(record.id)}" value="${escapeHtml(record.remark)}" placeholder="点击填写" aria-label="编辑备注" ${state.canWrite ? '' : 'disabled'} />
              </div>
            </div>

            <div class="code-strip">
              <div class="code-copy">
                <span class="field-label">短信验证码</span>
                <div class="code-result">${codeStatusMarkup(record)}</div>
              </div>
              <div class="code-meta">
                ${linkMarkup}
                ${linkCopyMarkup}
                <button class="refresh-button" type="button" data-action="refresh-code" data-record-id="${escapeHtml(record.id)}" data-write ${record.codeStatus === 'loading' || !state.canWrite ? 'disabled' : ''}>${record.codeStatus === 'loading' ? '读取中' : '刷新取码'}</button>
                ${record.codeCheckedAt ? `<span class="checked-at">${escapeHtml(formatCheckedAt(record.codeCheckedAt))}</span>` : ''}
              </div>
            </div>
          </div>
        </details>
      </article>`;
  }

  function recordMatches(record) {
    const haystack = [
      record.account,
      record.phone,
      record.country,
      record.birthDate,
      record.remark,
      ...(record.questions || []),
    ].join(' ').toLowerCase();
    const matchesQuery = !state.query || haystack.includes(state.query.toLowerCase());
    const matchesFilter = state.filter === 'all' || (state.filter === 'incomplete' && isIncomplete(record));
    return matchesQuery && matchesFilter;
  }

  function render() {
    const completeCount = state.records.filter((record) => !isIncomplete(record)).length;
    const incompleteCount = state.records.length - completeCount;
    elements.totalCount.textContent = state.records.length;
    elements.completeCount.textContent = completeCount;
    elements.incompleteCount.textContent = incompleteCount;

    document.querySelectorAll('[data-filter]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.filter === state.filter);
    });

    const filtered = state.records.filter(recordMatches);
    elements.recordsList.innerHTML = filtered.map(renderRecord).join('');
    const hasRecords = filtered.length > 0;
    elements.recordsList.hidden = !hasRecords;
    elements.emptyState.hidden = hasRecords;
    if (!hasRecords) {
      elements.emptyState.innerHTML = state.records.length
        ? '<strong>没有匹配的账号</strong><span>换一个关键词，或切换左侧筛选。</span>'
        : '<strong>档案柜还是空的</strong><span>把账号资料粘贴到上方，解析后就会出现在这里。</span>';
    }
  }

  function getRecordCard(id) {
    return [...elements.recordsList.querySelectorAll('.record-card')].find((card) => card.dataset.recordId === id);
  }

  function updatePasswordUI(record) {
    const card = getRecordCard(record.id);
    if (!card) return;
    const revealed = state.revealed.has(record.id);
    const passwordButton = card.querySelector('[data-field="password"]');
    const passwordText = passwordButton?.querySelector('span:first-child');
    if (passwordText) passwordText.textContent = revealed && record.password ? record.password : (record.password ? '••••••••' : '未填写');
    const toggleButton = card.querySelector('[data-action="toggle-password"]');
    if (toggleButton) {
      toggleButton.textContent = revealed ? '隐藏' : '显密';
      toggleButton.setAttribute('aria-label', revealed ? '隐藏密码' : '显示密码');
    }
  }

  function updateCodeUI(record) {
    const card = getRecordCard(record.id);
    if (!card) return;
    const result = card.querySelector('.code-result');
    if (result) result.innerHTML = codeStatusMarkup(record);
    const refreshButton = card.querySelector('[data-action="refresh-code"]');
    if (refreshButton) {
      refreshButton.disabled = record.codeStatus === 'loading' || !state.canWrite;
      refreshButton.textContent = record.codeStatus === 'loading' ? '读取中' : '刷新取码';
    }
    const meta = card.querySelector('.code-meta');
    if (meta) {
      const checkedAt = meta.querySelector('.checked-at') || document.createElement('span');
      checkedAt.className = 'checked-at';
      checkedAt.textContent = formatCheckedAt(record.codeCheckedAt);
      checkedAt.hidden = !record.codeCheckedAt;
      if (!checkedAt.parentElement) meta.append(checkedAt);
    }
  }

  function setFeedback(result, duplicateCount = 0) {
    const success = result.records.length;
    const errorCount = result.errors.length;
    const errorMarkup = result.errors.length
      ? `<div class="feedback-errors">${result.errors.map((error) => `<span>第 ${error.line} 行：${escapeHtml(error.message)}</span>`).join('')}</div>`
      : '';
    elements.importFeedback.innerHTML = `
      <div class="feedback-summary">
        <span class="feedback-main">已识别 <b>${success}</b> 条</span>
        ${duplicateCount ? `<span>更新重复账号 ${duplicateCount} 条</span>` : ''}
        ${errorCount ? `<span class="is-error">跳过 ${errorCount} 行</span>` : '<span class="is-success">格式检查通过</span>'}
      </div>${errorMarkup}`;
  }

  function fallbackCopy(value) {
    const textarea = document.createElement('textarea');
    textarea.value = value;
    textarea.setAttribute('readonly', '');
    textarea.style.position = 'fixed';
    textarea.style.opacity = '0';
    document.body.appendChild(textarea);
    textarea.select();
    const copied = document.execCommand('copy');
    textarea.remove();
    return copied;
  }

  async function copyValue(value, label) {
    if (!value) {
      notify(`${label}为空`, 'warning');
      return;
    }
    try {
      if (navigator.clipboard?.writeText) {
        await navigator.clipboard.writeText(value);
      } else if (!fallbackCopy(value)) {
        throw new Error('clipboard unavailable');
      }
      notify(`${label}已复制`, 'success');
    } catch {
      notify('复制失败，请手动选择内容', 'warning');
    }
  }

  function requestConfirmation(message, onConfirm, title = '确认操作') {
    if (!elements.confirmDialog?.showModal) {
      if (window.confirm(message)) onConfirm();
      return;
    }
    elements.confirmTitle.textContent = title;
    elements.confirmMessage.textContent = message;
    state.confirmAction = onConfirm;
    elements.confirmDialog.showModal();
  }

  function resolveConfirmation(accepted) {
    const action = state.confirmAction;
    state.confirmAction = null;
    elements.confirmDialog.close();
    if (accepted && action) action();
  }

  async function fetchTextWithTimeout(url) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = window.setTimeout(() => controller?.abort(), 8000);
    try {
      const response = await fetch(url, {
        ...(controller ? { signal: controller.signal } : {}),
        credentials: 'same-origin',
        headers: getRequestHeaders(url),
      });
      if (!response.ok) throw new Error(`HTTP ${response.status}`);
      return await response.text();
    } finally {
      window.clearTimeout(timer);
    }
  }

  async function refreshCode(id) {
    const record = state.records.find((item) => item.id === id);
    if (!record?.codeUrl) {
      notify('这条记录没有取码链接', 'warning');
      return;
    }
    if (!state.canWrite) {
      notify('共享库不可用，暂时不能刷新验证码', 'warning');
      return;
    }

    record.codeStatus = 'loading';
    record.codeError = '';
    record.codeCheckedAt = new Date().toISOString();
    updateCodeUI(record);

    try {
      let responseText;
      let lastError;
      for (const requestUrl of getCodeRequestUrls(record.codeUrl)) {
        try {
          responseText = await fetchTextWithTimeout(requestUrl);
          break;
        } catch (error) {
          lastError = error;
        }
      }
      if (responseText === undefined) throw lastError || new Error('code request failed');
      const code = extractSixDigitCode(responseText);
      record.smsCode = code;
      record.codeStatus = code ? 'found' : 'empty';
      record.codeError = '';
      notify(code ? '已读取到 6 位验证码' : '链接中没有符合条件的验证码', code ? 'success' : 'info');
    } catch {
      record.smsCode = '';
      record.codeStatus = 'blocked';
      record.codeError = getCodeFailureMessage(record.codeUrl);
      notify(`${record.codeError}，仍可点击链接查看`, 'warning');
    }
    record.codeCheckedAt = new Date().toISOString();
    updateCodeUI(record);
    touchRecord(record);
    try {
      await syncSnapshot(state.records, state.deleted, state.clearAt, { renderResult: false });
      updateCodeUI(state.records.find((item) => item.id === id) || record);
    } catch {
      updateCodeUI(record);
    }
  }

  function handleImport() {
    if (!state.canWrite) {
      notify('共享库不可用，当前为只读模式', 'warning');
      return;
    }
    const text = elements.importInput.value.trim();
    if (!text) {
      notify('先粘贴一段账号资料', 'warning');
      elements.importInput.focus();
      return;
    }

    const result = parseImport(text);
    if (!result.records.length) {
      setFeedback(result);
      notify('没有可导入的完整账号行', 'warning');
      return;
    }

    const merged = mergeRecords(state.records, result.records);
    setFeedback(result, merged.duplicateCount);
    syncSnapshot(merged.records, state.deleted, state.clearAt)
      .then(() => {
        elements.importInput.value = '';
        notify(`已保存 ${result.records.length} 条账号资料`, 'success');

        const importedAccounts = new Set(result.records.filter((record) => record.codeUrl).map((record) => record.account));
        state.records.filter((record) => importedAccounts.has(record.account)).forEach((record) => refreshCode(record.id));
      })
      .catch(() => {
        notify('服务器未确认保存，资料仍留在输入框中', 'warning');
      });
  }

  function handleExportAll() {
    if (!state.records.length) {
      notify('档案柜里没有可导出的账号', 'warning');
      return;
    }

    const content = formatExportText(state.records);
    const blob = new Blob([content], { type: 'text/plain;charset=utf-8' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `apple-id-vault-${new Date().toISOString().slice(0, 10)}.txt`;
    document.body.append(link);
    link.click();
    link.remove();
    window.setTimeout(() => URL.revokeObjectURL(url), 0);
    notify(`已导出 ${state.records.length} 条账号资料`, 'success');
  }

  function deleteRecord(id) {
    const record = state.records.find((item) => item.id === id);
    if (!record) return;
    requestConfirmation(`确定删除账号“${record.account}”吗？`, () => {
      if (!state.canWrite) {
        notify('共享库不可用，当前为只读模式', 'warning');
        return;
      }
      const nextRecords = state.records.filter((item) => item.id !== id);
      const nextDeleted = { ...state.deleted, [record.account]: new Date().toISOString() };
      syncSnapshot(nextRecords, nextDeleted, state.clearAt)
        .then(() => {
          state.revealed.delete(id);
          notify('账号已删除', 'success');
        })
        .catch(() => notify('服务器未确认删除，资料未改变', 'warning'));
    }, '删除这条档案？');
  }

  function clearAll() {
    if (!state.records.length) {
      notify('档案柜已经是空的', 'info');
      return;
    }
    requestConfirmation('确定清空全部账号资料吗？此操作不可恢复。', () => {
      if (!state.canWrite) {
        notify('共享库不可用，当前为只读模式', 'warning');
        return;
      }
      clearServerState()
        .then(() => {
          state.revealed.clear();
          notify('全部账号资料已清空', 'success');
        })
        .catch((error) => {
          setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
          notify('服务器未确认清空，资料未改变', 'warning');
        });
    }, '清空全部档案？');
  }

  elements.parseButton.addEventListener('click', handleImport);
  elements.exportAllButton.addEventListener('click', handleExportAll);
  elements.clearAllButton.addEventListener('click', clearAll);
  elements.syncButton.addEventListener('click', () => loadServerState());
  elements.authForm?.addEventListener('submit', handleAuthSubmit);
  elements.authDialog?.addEventListener('cancel', (event) => event.preventDefault());
  elements.searchInput.addEventListener('input', (event) => {
    state.query = event.target.value.trim();
    render();
  });

  document.addEventListener('click', (event) => {
    const confirmationTarget = event.target.closest('[data-confirm]');
    if (confirmationTarget) {
      resolveConfirmation(confirmationTarget.dataset.confirm === 'accept');
      return;
    }

    const filterButton = event.target.closest('[data-filter]');
    if (filterButton) {
      state.filter = filterButton.dataset.filter;
      render();
      return;
    }

    const actionTarget = event.target.closest('[data-action]');
    if (!actionTarget) return;
    const { action, recordId, field } = actionTarget.dataset;
    const record = state.records.find((item) => item.id === recordId);
    if (!record) return;

    if (action === 'copy') {
      const value = getFieldValue(record, field);
      const labels = { verificationCode: '验证码', phone: '手机号', codeUrl: '取码链接' };
      copyValue(value, labels[field] || '内容');
    } else if (action === 'toggle-password') {
      if (state.revealed.has(recordId)) state.revealed.delete(recordId);
      else state.revealed.add(recordId);
      updatePasswordUI(record);
    } else if (action === 'refresh-code') {
      refreshCode(recordId);
    } else if (action === 'delete') {
      deleteRecord(recordId);
    }
  });

  document.addEventListener('input', (event) => {
    const remarkInput = event.target.closest('[data-action="update-remark"]');
    if (!remarkInput) return;
    const record = state.records.find((item) => item.id === remarkInput.dataset.recordId);
    if (!record) return;
    if (!state.canWrite && state.syncStatus !== 'syncing') {
      notify('共享库不可用，备注暂时不能保存', 'warning');
      return;
    }
    record.remark = remarkInput.value;
    touchRecord(record);
    window.clearTimeout(state.remarkTimers.get(record.id));
    state.remarkTimers.set(record.id, window.setTimeout(() => {
      syncSnapshot(state.records, state.deleted, state.clearAt, { renderResult: false })
        .catch(() => notify('服务器未确认备注保存，已切换只读模式', 'warning'));
    }, 350));
  });

  elements.confirmDialog.addEventListener('cancel', () => {
    state.confirmAction = null;
  });

  render();
  if (state.authHeader) {
    setSyncStatus('loading');
    loadServerState(true);
  } else {
    setSyncStatus('auth');
    showAuthDialog();
  }
})();
