(() => {
  'use strict';

  const STORAGE_KEY = 'apple-id-vault-records';
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

  function createParsedRecord(accountData) {
    return {
      id: makeId(),
      ...accountData,
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

  function getCodeRequestUrls(url, pageProtocol = typeof location === 'undefined' ? 'https:' : location.protocol) {
    const source = asText(url);
    try {
      const parsed = new URL(source);
      if (pageProtocol === 'https:' && parsed.protocol === 'http:') {
        parsed.protocol = 'https:';
        return [parsed.href, source];
      }
    } catch {
      return [source];
    }
    return [source];
  }

  function getCodeFailureMessage(url, pageProtocol = typeof location === 'undefined' ? 'https:' : location.protocol) {
    try {
      const parsed = new URL(url);
      if (pageProtocol === 'https:' && parsed.protocol === 'http:') {
        return '取码链接是 HTTP，HTTPS 页面无法自动读取';
      }
    } catch {
      return '取码链接格式无效';
    }
    return '取码链接未开放 CORS，无法自动读取';
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
    console.assert(getCodeRequestUrls('http://sms.test/code', 'https:')[0] === 'https://sms.test/code');
    console.assert(getCodeFailureMessage('http://sms.test/code', 'https:').includes('HTTP'));
    console.assert(getCodeFailureMessage('https://sms.test/code', 'https:').includes('CORS'));
    console.log('parser self-check: ok');
  }

  const api = {
    parseImport,
    parseAccountLine,
    parseContactLine,
    extractSixDigitCode,
    isIncomplete,
    loadRecords,
    saveRecords,
    mergeRecords,
  };

  if (typeof module !== 'undefined' && module.exports) module.exports = api;
  runSelfCheck();

  if (typeof document === 'undefined') return;

  const state = {
    records: loadRecords(),
    filter: 'all',
    query: '',
    revealed: new Set(),
    toastTimer: null,
  };

  const elements = {
    importInput: document.querySelector('#importInput'),
    parseButton: document.querySelector('#parseButton'),
    clearAllButton: document.querySelector('#clearAllButton'),
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
    toast: document.querySelector('#toast'),
  };

  state.confirmAction = null;

  function notify(message, tone = 'info') {
    if (!elements.toast) return;
    window.clearTimeout(state.toastTimer);
    elements.toast.textContent = message;
    elements.toast.dataset.tone = tone;
    elements.toast.classList.add('is-visible');
    state.toastTimer = window.setTimeout(() => elements.toast.classList.remove('is-visible'), 2600);
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
      const reason = record.codeError || '取码链接未开放 CORS，无法自动读取';
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
        <div class="record-head">
          <div class="record-identity">
            <span class="record-index">ID / ${escapeHtml(record.account.slice(0, 2).toUpperCase() || '—')}</span>
            <h3>${escapeHtml(record.account || '未命名账号')}</h3>
            <span class="status-pill ${incomplete ? 'is-warning' : 'is-ready'}"><i></i>${statusLabel}</span>
          </div>
          <div class="record-actions">
            <button class="icon-button" type="button" data-action="toggle-password" data-record-id="${escapeHtml(record.id)}" aria-label="${state.revealed.has(record.id) ? '隐藏密码' : '显示密码'}">${state.revealed.has(record.id) ? '隐藏' : '显密'}</button>
            <button class="icon-button is-danger" type="button" data-action="delete" data-record-id="${escapeHtml(record.id)}" aria-label="删除账号">删除</button>
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
        </div>

        <div class="code-strip">
          <div class="code-copy">
            <span class="field-label">短信验证码</span>
            <div class="code-result">${codeStatusMarkup(record)}</div>
          </div>
          <div class="code-meta">
            ${linkMarkup}
            ${linkCopyMarkup}
            <button class="refresh-button" type="button" data-action="refresh-code" data-record-id="${escapeHtml(record.id)}" ${record.codeStatus === 'loading' ? 'disabled' : ''}>${record.codeStatus === 'loading' ? '读取中' : '刷新取码'}</button>
            ${record.codeCheckedAt ? `<span class="checked-at">${escapeHtml(formatCheckedAt(record.codeCheckedAt))}</span>` : ''}
          </div>
        </div>
      </article>`;
  }

  function recordMatches(record) {
    const haystack = [
      record.account,
      record.phone,
      record.country,
      record.birthDate,
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
      refreshButton.disabled = record.codeStatus === 'loading';
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
      const response = await fetch(url, controller ? { signal: controller.signal } : undefined);
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

    record.codeStatus = 'loading';
    record.codeError = '';
    record.codeCheckedAt = new Date().toISOString();
    saveRecords(state.records);
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
    saveRecords(state.records);
    updateCodeUI(record);
  }

  function handleImport() {
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
    state.records = merged.records;
    saveRecords(state.records);
    setFeedback(result, merged.duplicateCount);
    elements.importInput.value = '';
    render();
    notify(`已保存 ${result.records.length} 条账号资料`, 'success');

    const importedAccounts = new Set(result.records.filter((record) => record.codeUrl).map((record) => record.account));
    state.records.filter((record) => importedAccounts.has(record.account)).forEach((record) => refreshCode(record.id));
  }

  function deleteRecord(id) {
    const record = state.records.find((item) => item.id === id);
    if (!record) return;
    requestConfirmation(`确定删除账号“${record.account}”吗？`, () => {
      state.records = state.records.filter((item) => item.id !== id);
      state.revealed.delete(id);
      saveRecords(state.records);
      render();
      notify('账号已删除', 'success');
    }, '删除这条档案？');
  }

  function clearAll() {
    if (!state.records.length) {
      notify('档案柜已经是空的', 'info');
      return;
    }
    requestConfirmation('确定清空全部账号资料吗？此操作不可恢复。', () => {
      state.records = [];
      state.revealed.clear();
      saveRecords(state.records);
      render();
      notify('全部账号资料已清空', 'success');
    }, '清空全部档案？');
  }

  elements.parseButton.addEventListener('click', handleImport);
  elements.clearAllButton.addEventListener('click', clearAll);
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

  elements.confirmDialog.addEventListener('cancel', () => {
    state.confirmAction = null;
  });

  render();
})();
