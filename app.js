(() => {
  'use strict';

  const STORAGE_KEY = 'apple-id-vault-records';
  const AUTH_STORAGE_KEY = 'apple-id-vault-auth';
  const REQUEST_TIMEOUT_MS = 11000;
  const SCHEMA_VERSION = 2;
  const MAX_GROUP_SIZE = 6;
  const VALID_CODE_STATUSES = new Set(['idle', 'loading', 'found', 'empty', 'blocked']);
  const VALID_PROFILE_STATUSES = new Set(['complete', 'incomplete']);
  const CODE_LABEL_RE = /(?:验证码|校验码|动态码|安全码|短信码|一次性密码|otp\b|one[-\s]?time(?:\s+password)?|verification(?:\s+code)?|security\s+code|passcode|\bcode\b)/iu;

  function asText(value) {
    return value == null ? '' : String(value);
  }

  function clean(value) {
    return asText(value).trim().replace(/\s+/g, ' ');
  }

  function normalizeCodeUrl(value) {
    const source = clean(value);
    if (!source) return '';
    try {
      const parsed = new URL(source);
      return ['http:', 'https:'].includes(parsed.protocol) && parsed.hostname ? source : '';
    } catch {
      return '';
    }
  }

  function shouldRetryVaultRequest(error, attempt) {
    const status = Number(error?.status || 0);
    return attempt < 1 && (!status || status >= 500);
  }

  function isVaultWritable(status, authHeader, hasLoadedState) {
    return Boolean(authHeader) && hasLoadedState && ['ready', 'error'].includes(status);
  }

  function canQueueVaultWrite(status, authHeader, hasLoadedState) {
    return Boolean(authHeader) && hasLoadedState && ['ready', 'syncing', 'error'].includes(status);
  }

  function getVaultWriteUnavailableMessage(status) {
    if (status === 'auth') return '请先完成门禁验证';
    if (status === 'loading' || status === 'syncing') return '共享库正在同步，请稍后重试';
    if (status === 'error') return '共享库连接波动，请点击刷新同步';
    return '共享库暂未连接，请点击刷新同步';
  }

  function makeId() {
    try {
      if (globalThis.crypto?.randomUUID) return globalThis.crypto.randomUUID();
    } catch {
      // Fall through to the local fallback when randomUUID is unavailable.
    }
    return `${Date.now().toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  function nextTimestamp(previousValue = '') {
    const previous = Date.parse(previousValue) || 0;
    return new Date(Math.max(Date.now(), previous + 1)).toISOString();
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

  function parseMetadataLine(line) {
    const match = asText(line).match(/^(备注|副邮箱|专用密码|分组|标记|主号|手机号|取码链接)(?:\||：|:)\s*(.*)$/u);
    if (!match) return null;
    const [, label, rawValue] = match;
    const value = rawValue.trim();
    if (label === '备注') return { field: 'remark', value: clean(value), flag: 'hasRemark' };
    if (label === '副邮箱') return { field: 'secondaryEmail', value: clean(value), flag: 'hasSecondaryEmail' };
    if (label === '专用密码') return { field: 'appPassword', value, flag: 'hasAppPassword' };
    if (label === '分组') return { field: 'importGroupName', value: clean(value), flag: 'hasGroup' };
    if (label === '标记') {
      return { field: 'profileStatus', value: value === '完善' ? 'complete' : 'incomplete', flag: 'hasProfileStatus' };
    }
    if (label === '主号') return { field: 'isPrimary', value: /^(?:是|true|1)$/iu.test(value), flag: 'hasPrimary' };
    if (label === '手机号') return { field: 'phone', value: clean(value), flag: 'hasPhone' };
    const codeUrl = normalizeCodeUrl(value);
    return { field: 'codeUrl', value: codeUrl, flag: 'hasCodeUrl', error: value && !codeUrl ? '取码链接必须是 http 或 https 地址' : '' };
  }

  function createParsedRecord(accountData) {
    return {
      id: makeId(),
      ...accountData,
      remark: '',
      secondaryEmail: '',
      appPassword: '',
      profileStatus: '',
      importGroupName: '',
      isPrimary: false,
      phone: '',
      codeUrl: '',
      hasContact: false,
      hasPhone: false,
      hasCodeUrl: false,
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

      const metadata = parseMetadataLine(line);
      if (metadata) {
        if (!records.length) {
          errors.push({ line: index + 1, raw: line, message: '资料附加行需要放在账号行后面' });
          return;
        }
        if (metadata.error) {
          errors.push({ line: index + 1, raw: line, message: metadata.error });
          return;
        }
        const record = records[records.length - 1];
        record[metadata.field] = metadata.value;
        record[metadata.flag] = true;
        if (metadata.flag === 'hasPhone' || metadata.flag === 'hasCodeUrl') record.hasContact = true;
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

        Object.assign(record, contact, { hasContact: true, hasPhone: true, hasCodeUrl: true });
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
    const coreValues = [record.account, record.password, ...questions.slice(0, 3), record.birthDate, record.country];
    const profileStatus = VALID_PROFILE_STATUSES.has(record.profileStatus)
      ? record.profileStatus
      : (questions.length >= 3 && coreValues.every((value) => clean(value)) ? 'complete' : 'incomplete');
    const groupOrder = Math.max(0, Number.parseInt(record.groupOrder, 10) || 0);

    return {
      id: clean(record.id) || makeId(),
      account: clean(record.account),
      password: asText(record.password),
      questions: [0, 1, 2].map((index) => clean(questions[index])),
      birthDate: clean(record.birthDate),
      country: clean(record.country),
      remark: clean(record.remark),
      phone: clean(record.phone),
      codeUrl: normalizeCodeUrl(record.codeUrl),
      smsCode: /^\d{6}$/.test(asText(record.smsCode)) ? asText(record.smsCode) : '',
      codeStatus,
      codeError: clean(record.codeError),
      codeCheckedAt: clean(record.codeCheckedAt),
      secondaryEmail: clean(record.secondaryEmail),
      appPassword: asText(record.appPassword),
      profileStatus,
      groupId: clean(record.groupId),
      groupOrder,
      isPrimary: record.isPrimary === true,
      updatedAt: clean(record.updatedAt) || new Date().toISOString(),
    };
  }

  function normalizeGroup(group) {
    if (!group || typeof group !== 'object') return null;
    const id = clean(group.id);
    const name = clean(group.name);
    if (!id || !name) return null;
    return { id, name, updatedAt: clean(group.updatedAt) || new Date().toISOString() };
  }

  function normalizeVaultLayout(records, groups) {
    const normalizedGroups = (Array.isArray(groups) ? groups : []).map(normalizeGroup).filter(Boolean);
    const groupIds = new Set(normalizedGroups.map((group) => group.id));
    const normalizedRecords = (Array.isArray(records) ? records : []).map(normalizeRecord).filter(Boolean);
    const members = new Map(normalizedGroups.map((group) => [group.id, []]));

    normalizedRecords.forEach((record) => {
      if (!groupIds.has(record.groupId)) {
        Object.assign(record, { groupId: '', groupOrder: 0, isPrimary: false });
        return;
      }
      members.get(record.groupId).push(record);
    });

    members.forEach((groupRecords) => {
      groupRecords.sort((left, right) => left.groupOrder - right.groupOrder || left.account.localeCompare(right.account));
      let primaryKept = false;
      groupRecords.forEach((record, index) => {
        if (index >= MAX_GROUP_SIZE) {
          Object.assign(record, { groupId: '', groupOrder: 0, isPrimary: false });
          return;
        }
        record.groupOrder = index;
        record.isPrimary = record.isPrimary && !primaryKept;
        primaryKept ||= record.isPrimary;
      });
    });
    return normalizedRecords;
  }

  function moveRecordWithinGroup(records, recordId, direction) {
    const target = records.find((record) => record.id === recordId);
    if (!target?.groupId || ![-1, 1].includes(direction)) return records;
    const members = records
      .filter((record) => record.groupId === target.groupId)
      .sort((left, right) => left.groupOrder - right.groupOrder || left.account.localeCompare(right.account));
    const index = members.findIndex((record) => record.id === recordId);
    const swapIndex = index + direction;
    if (index < 0 || swapIndex < 0 || swapIndex >= members.length) return records;
    [members[index], members[swapIndex]] = [members[swapIndex], members[index]];
    const orderById = new Map(members.map((record, order) => [record.id, order]));
    return records.map((record) => orderById.has(record.id) ? { ...record, groupOrder: orderById.get(record.id) } : record);
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
      const legacyFullContact = candidate.hasContact === true && candidate.hasPhone === undefined && candidate.hasCodeUrl === undefined;
      const hasPhone = candidate.hasPhone === true || legacyFullContact;
      const hasCodeUrl = candidate.hasCodeUrl === true || legacyFullContact;
      const codeChanged = hasCodeUrl && normalized.codeUrl !== previous.codeUrl;
      const next = {
        ...previous,
        ...normalized,
        id: previous.id,
        account: previous.account,
        password: previous.password,
        remark: candidate.hasRemark ? normalized.remark : previous.remark,
        secondaryEmail: candidate.hasSecondaryEmail ? normalized.secondaryEmail : previous.secondaryEmail,
        appPassword: candidate.hasAppPassword ? normalized.appPassword : previous.appPassword,
        profileStatus: candidate.hasProfileStatus ? normalized.profileStatus : previous.profileStatus,
        groupId: previous.groupId,
        groupOrder: previous.groupOrder,
        isPrimary: candidate.hasPrimary ? normalized.isPrimary : previous.isPrimary,
        updatedAt: nextTimestamp(previous.updatedAt),
      };

      next.phone = hasPhone ? normalized.phone : previous.phone;
      next.codeUrl = hasCodeUrl ? normalized.codeUrl : previous.codeUrl;

      if (!codeChanged) {
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

  function applyImportedGroups(records, imported, groups) {
    const nextGroups = groups.map((group) => ({ ...group }));
    const groupByName = new Map(nextGroups.map((group) => [group.name.toLocaleLowerCase(), group]));
    const assignments = new Map();
    const createdGroupIds = [];
    const nextOrder = new Map();

    imported.forEach((candidate) => {
      if (!candidate.hasGroup || !candidate.account) return;
      const name = clean(candidate.importGroupName).slice(0, 80);
      const groupKey = name.toLocaleLowerCase();
      let group = name ? groupByName.get(groupKey) : null;
      if (name && !group) {
        group = { id: makeId(), name, updatedAt: new Date().toISOString() };
        nextGroups.push(group);
        groupByName.set(groupKey, group);
        createdGroupIds.push(group.id);
      }
      const groupId = group?.id || '';
      if (groupId && !nextOrder.has(groupId)) {
        const sameGroupImports = new Set(imported.filter((item) => clean(item.importGroupName).toLocaleLowerCase() === groupKey).map((item) => item.account));
        nextOrder.set(groupId, records.filter((record) => record.groupId === groupId && !sameGroupImports.has(record.account)).length);
      }
      assignments.set(candidate.account, {
        groupId,
        groupOrder: groupId ? (nextOrder.get(groupId) || 0) : 0,
        hasPrimary: candidate.hasPrimary,
        isPrimary: candidate.isPrimary,
      });
      if (groupId) nextOrder.set(groupId, (nextOrder.get(groupId) || 0) + 1);
    });

    const nextRecords = records.map((record) => ({ ...record }));
    const counts = new Map(nextGroups.map((group) => [group.id, nextRecords.filter((record) => record.groupId === group.id).length]));
    let overflowCount = 0;

    assignments.forEach((assignment, account) => {
      const record = nextRecords.find((item) => item.account === account);
      if (!record) return;
      const previousGroupId = record.groupId;
      if (assignment.groupId !== previousGroupId) {
        if (assignment.groupId && (counts.get(assignment.groupId) || 0) >= MAX_GROUP_SIZE) {
          overflowCount += 1;
          return;
        }
        if (previousGroupId) counts.set(previousGroupId, Math.max(0, (counts.get(previousGroupId) || 0) - 1));
        record.groupId = assignment.groupId;
        record.groupOrder = assignment.groupId ? (counts.get(assignment.groupId) || 0) : 0;
        record.isPrimary = false;
        if (assignment.groupId) counts.set(assignment.groupId, (counts.get(assignment.groupId) || 0) + 1);
      }
      if (assignment.groupId) record.groupOrder = assignment.groupOrder;
      if (assignment.hasPrimary) {
        if (assignment.isPrimary && record.groupId) {
          nextRecords.forEach((item) => {
            if (item.groupId === record.groupId) item.isPrimary = false;
          });
          record.isPrimary = true;
        } else {
          record.isPrimary = false;
        }
      }
      record.updatedAt = nextTimestamp(record.updatedAt);
    });

    return {
      records: normalizeVaultLayout(nextRecords, nextGroups),
      groups: nextGroups,
      createdGroupIds,
      overflowCount,
    };
  }

  function formatRecordForExport(record, groups = []) {
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
    else {
      if (normalized.phone) lines.push(`手机号|${normalized.phone}`);
      if (normalized.codeUrl) lines.push(`取码链接|${normalized.codeUrl}`);
    }
    if (normalized.secondaryEmail) lines.push(`副邮箱|${normalized.secondaryEmail}`);
    if (normalized.appPassword) lines.push(`专用密码|${normalized.appPassword}`);
    if (normalized.remark) lines.push(`备注|${normalized.remark}`);
    const groupName = groups.find((group) => group.id === normalized.groupId)?.name;
    if (groupName) lines.push(`分组|${groupName}`);
    lines.push(`标记|${normalized.profileStatus === 'complete' ? '完善' : '未完善'}`);
    if (normalized.isPrimary) lines.push('主号|是');
    return lines.join('\n');
  }

  function formatExportText(records, groups = []) {
    const groupIndex = new Map(groups.map((group, index) => [group.id, index]));
    return (Array.isArray(records) ? records : [])
      .map((record, index) => ({ record, index }))
      .sort((leftItem, rightItem) => {
        const left = leftItem.record;
        const right = rightItem.record;
        const leftGroup = groupIndex.has(left.groupId) ? groupIndex.get(left.groupId) : groups.length;
        const rightGroup = groupIndex.has(right.groupId) ? groupIndex.get(right.groupId) : groups.length;
        if (leftGroup !== rightGroup) return leftGroup - rightGroup;
        if (left.groupId && right.groupId) return left.groupOrder - right.groupOrder || left.account.localeCompare(right.account);
        return leftItem.index - rightItem.index;
      })
      .map(({ record }) => formatRecordForExport(record, groups))
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
    const groups = Array.isArray(payload?.groups) ? payload.groups.map(normalizeGroup).filter(Boolean) : [];
    const records = Array.isArray(payload?.records)
      ? payload.records.map(normalizeRecord).filter((record) => record?.account)
      : [];
    const deleted = {};
    if (payload?.deleted && typeof payload.deleted === 'object') {
      Object.entries(payload.deleted).forEach(([account, timestamp]) => {
        if (account && timestamp) deleted[account] = clean(timestamp);
      });
    }
    const deletedGroups = {};
    if (payload?.deletedGroups && typeof payload.deletedGroups === 'object') {
      Object.entries(payload.deletedGroups).forEach(([groupId, timestamp]) => {
        if (groupId && timestamp) deletedGroups[groupId] = clean(timestamp);
      });
    }
    return {
      revision: Number.isFinite(Number(payload?.revision)) ? Number(payload.revision) : 0,
      records: normalizeVaultLayout(records, groups),
      groups,
      deleted,
      deletedGroups,
      clearAt: clean(payload?.clearAt),
    };
  }

  async function fetchJsonWithTimeout(url, options = {}) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = window.setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
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
    const splitContact = parseImport('split@example.com----pass----Q1----Q2----Q3----1984/2/25----美国\n手机号|+18178668072\n取码链接|https://example.com/split');
    console.assert(splitContact.records[0]?.phone === '+18178668072');
    console.assert(splitContact.records[0]?.codeUrl === 'https://example.com/split');
    console.assert(parseImport('unsafe@example.com----pass----Q1----Q2----Q3----1984/2/25----美国\n取码链接|javascript:alert(1)').errors.length === 1);

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
    console.assert(exported === 'a@example.com----secret----Q1----Q2----Q3----1984/2/25----美国\n+18178668072|https://example.com/code\n备注|长期使用\n标记|完善');
    console.assert(parseImport(exported).records[0]?.remark === '长期使用');
    console.assert(shouldRetryVaultRequest(new Error('timeout'), 0) === true);
    console.assert(shouldRetryVaultRequest({ status: 500 }, 0) === true);
    console.assert(shouldRetryVaultRequest({ status: 401 }, 0) === false);
    console.assert(shouldRetryVaultRequest({ status: 400 }, 0) === false);
    console.assert(isVaultWritable('ready', 'Basic test', true) === true);
    console.assert(isVaultWritable('error', 'Basic test', true) === true);
    console.assert(isVaultWritable('error', 'Basic test', false) === false);
    console.assert(isVaultWritable('error', '') === false);
    console.assert(isVaultWritable('syncing', 'Basic test', true) === false);
    console.assert(canQueueVaultWrite('ready', 'Basic test', true) === true);
    console.assert(canQueueVaultWrite('syncing', 'Basic test', true) === true);
    console.assert(canQueueVaultWrite('error', 'Basic test', true) === true);
    console.assert(canQueueVaultWrite('error', 'Basic test', false) === false);
    const legacyProfile = normalizeRecord({
      account: 'legacy@example.com',
      password: 'secret',
      questions: ['Q1', 'Q2', 'Q3'],
      birthDate: '1984/2/25',
      country: '美国',
    });
    console.assert(legacyProfile.profileStatus === 'complete');
    console.assert(legacyProfile.secondaryEmail === '' && legacyProfile.appPassword === '');
    const group = normalizeGroup({ id: 'g1', name: '常用', updatedAt: '2026-08-13T00:00:00Z' });
    const grouped = normalizeVaultLayout(Array.from({ length: 7 }, (_, index) => normalizeRecord({
      account: `grouped${index}@example.com`,
      groupId: 'g1',
      groupOrder: 6 - index,
      isPrimary: index === 0 || index === 6,
    })), [group]);
    console.assert(grouped.filter((record) => record.groupId === 'g1').length === 6);
    console.assert(grouped.filter((record) => record.groupId === 'g1' && record.isPrimary).length === 1);
    console.assert(grouped.filter((record) => !record.groupId).every((record) => !record.isPrimary));
    const firstGrouped = grouped.filter((record) => record.groupId === 'g1').sort((left, right) => left.groupOrder - right.groupOrder)[0];
    const moved = moveRecordWithinGroup(grouped, firstGrouped.id, 1);
    console.assert(moved.find((record) => record.id === firstGrouped.id).groupOrder === 1);
    const groupedExport = formatExportText([{ ...legacyProfile, secondaryEmail: 'backup@example.com', appPassword: 'app-pass', groupId: 'g1', isPrimary: true }], [group]);
    const groupedImport = parseImport(groupedExport).records[0];
    console.assert(groupedImport.secondaryEmail === 'backup@example.com');
    console.assert(groupedImport.appPassword === 'app-pass');
    console.assert(groupedImport.importGroupName === '常用');
    console.assert(groupedImport.isPrimary === true);
    const restoredGroups = applyImportedGroups([legacyProfile], [{ ...groupedImport, account: legacyProfile.account }], []);
    console.assert(restoredGroups.groups[0]?.name === '常用');
    console.assert(restoredGroups.records[0]?.groupId === restoredGroups.groups[0]?.id);
    console.assert(restoredGroups.records[0]?.isPrimary === true);
    const orderedExport = formatExportText([
      { ...legacyProfile, account: 'second@example.com', groupId: 'g1', groupOrder: 1 },
      { ...legacyProfile, account: 'first@example.com', groupId: 'g1', groupOrder: 0 },
    ], [group]);
    console.assert(orderedExport.indexOf('first@example.com') < orderedExport.indexOf('second@example.com'));
    const orderedImport = parseImport(orderedExport).records;
    const restoredOrder = applyImportedGroups(orderedImport.map(normalizeRecord), orderedImport, []);
    console.assert(restoredOrder.records.find((record) => record.account === 'first@example.com').groupOrder === 0);
    console.assert(restoredOrder.records.find((record) => record.account === 'second@example.com').groupOrder === 1);
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
    normalizeGroup,
    normalizeVaultLayout,
    moveRecordWithinGroup,
    applyImportedGroups,
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
    groups: [],
    deleted: {},
    deletedGroups: {},
    clearAt: '',
    serverStateLoaded: false,
    filter: 'all',
    query: '',
    revealed: new Set(),
    editing: new Set(),
    expandedGroups: new Set(),
    expandedRecords: new Set(),
    editingGroupId: '',
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
    createGroupButton: document.querySelector('#createGroupButton'),
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
    groupDialog: document.querySelector('#groupDialog'),
    groupForm: document.querySelector('#groupForm'),
    groupDialogTitle: document.querySelector('#groupDialogTitle'),
    groupNameInput: document.querySelector('#groupNameInput'),
    groupError: document.querySelector('#groupError'),
    cancelGroupButton: document.querySelector('#cancelGroupButton'),
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
      control.disabled = !writable || control.hasAttribute('data-write-blocked');
    });
  }

  function setSyncStatus(status, message) {
    state.syncStatus = status;
    state.canWrite = isVaultWritable(status, state.authHeader, state.serverStateLoaded);
    const labels = {
      loading: '连接共享库…',
      syncing: '同步中…',
      ready: '已连接 · 共享库',
      auth: '等待门禁登录',
      error: '连接波动 · 可重试',
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

  function requireVaultAuthentication(message, fallbackRecords = state.records) {
    setAuthHeader('');
    state.records = fallbackRecords;
    setSyncStatus('auth');
    render();
    showAuthDialog(message);
  }

  function applyServerState(payload) {
    const next = normalizeServerState(payload);
    if (state.serverStateLoaded && next.revision < state.revision) return false;
    if (!state.serverStateLoaded) {
      next.groups.forEach((group) => state.expandedGroups.add(group.id));
      if (next.records.some((record) => !record.groupId)) state.expandedGroups.add('');
    }
    state.records = next.records;
    state.groups = next.groups;
    state.revision = next.revision;
    state.deleted = next.deleted;
    state.deletedGroups = next.deletedGroups;
    state.clearAt = next.clearAt;
    state.serverStateLoaded = true;
    const recordIds = new Set(state.records.map((record) => record.id));
    const groupIds = new Set(['', ...state.groups.map((group) => group.id)]);
    state.editing.forEach((id) => { if (!recordIds.has(id)) state.editing.delete(id); });
    state.revealed.forEach((id) => { if (!recordIds.has(id)) state.revealed.delete(id); });
    state.expandedRecords.forEach((id) => { if (!recordIds.has(id)) state.expandedRecords.delete(id); });
    state.expandedGroups.forEach((id) => { if (!groupIds.has(id)) state.expandedGroups.delete(id); });
    return true;
  }

  function touchRecord(record) {
    record.updatedAt = nextTimestamp(record.updatedAt);
    return record.updatedAt;
  }

  function getSyncErrorMessage(error) {
    if (error?.name === 'AbortError') return '共享库请求超时';
    return error?.message || '共享库暂时无法连接';
  }

  async function requestVault(path, options = {}) {
    const url = getVaultApiUrl(path);
    if (!url) throw new Error('共享库地址无效');
    const method = asText(options.method || 'GET').toUpperCase();
    const canRetry = method === 'GET';
    for (let attempt = 0; ; attempt += 1) {
      try {
        return await fetchJsonWithTimeout(url, {
          ...options,
          headers: getRequestHeaders(url, options.headers || {}),
        });
      } catch (error) {
        if (!canRetry || !shouldRetryVaultRequest(error, attempt)) throw error;
        await new Promise((resolve) => window.setTimeout(resolve, 350));
      }
    }
  }

  function syncSnapshot(records, deleted = state.deleted, clearAt = state.clearAt, options = {}) {
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      return Promise.reject(new Error(getVaultWriteUnavailableMessage(state.syncStatus)));
    }
    const { renderResult = true, migrate = false } = options;
    const snapshot = {
      records: records.map(normalizeRecord).filter((record) => record?.account),
      groups: state.groups.map(normalizeGroup).filter(Boolean),
      deleted: { ...deleted },
      deletedGroups: { ...state.deletedGroups },
      clearAt,
      schemaVersion: SCHEMA_VERSION,
      migrate,
    };
    const task = state.syncQueue.then(async () => {
      if (!state.authHeader || !state.serverStateLoaded) throw new Error(getVaultWriteUnavailableMessage(state.syncStatus));
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
        if (error?.status === 401) requireVaultAuthentication('门禁已失效，请重新验证');
        else setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
        throw error;
      }
    });
    state.syncQueue = task.catch(() => {});
    return task;
  }

  function clearServerState() {
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      return Promise.reject(new Error(getVaultWriteUnavailableMessage(state.syncStatus)));
    }
    const task = state.syncQueue.then(async () => {
      if (!state.authHeader || !state.serverStateLoaded) throw new Error(getVaultWriteUnavailableMessage(state.syncStatus));
      setSyncStatus('syncing');
      try {
        const payload = await requestVault('clear', { method: 'POST' });
        applyServerState(payload);
        setSyncStatus('ready');
        render();
        return payload;
      } catch (error) {
        if (error?.status === 401) requireVaultAuthentication('门禁已失效，请重新验证');
        else setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
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
        requireVaultAuthentication('门禁密码不正确，请重试', fallbackRecords);
        return;
      }
      state.records = fallbackRecords;
      setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
      render();
      notify('共享库连接波动，可点击刷新同步重试', 'warning');
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

  function renderEditField(record, field, label, value, options = {}) {
    const { type = 'text', className = '', placeholder = '未填写' } = options;
    return `
      <div class="data-field ${className}">
        <label class="field-label" for="edit-${escapeHtml(field)}-${escapeHtml(record.id)}">${escapeHtml(label)}</label>
        <input class="edit-input" id="edit-${escapeHtml(field)}-${escapeHtml(record.id)}" type="${escapeHtml(type)}"
          data-edit-field="${escapeHtml(field)}" value="${escapeHtml(value)}" placeholder="${escapeHtml(placeholder)}" />
      </div>`;
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
    const incomplete = record.profileStatus !== 'complete';
    const editing = state.editing.has(record.id);
    const groupMembers = record.groupId
      ? state.records.filter((item) => item.groupId === record.groupId).sort((left, right) => left.groupOrder - right.groupOrder)
      : [];
    const memberIndex = groupMembers.findIndex((item) => item.id === record.id);
    const statusLabel = incomplete ? '未完善' : '完善';
    const phoneMarkup = record.phone
      ? `<button class="phone-value" type="button" data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="phone" aria-label="复制手机号">${escapeHtml(record.phone)}<span>复制</span></button>`
      : '<span class="muted-value">未绑定手机号</span>';
    const linkMarkup = record.codeUrl
      ? `<a class="link-value" href="${escapeHtml(record.codeUrl)}" target="_blank" rel="noreferrer">打开取码链接 <span>↗</span></a>`
      : '<span class="muted-value">未绑定取码链接</span>';
    const linkCopyMarkup = record.codeUrl
      ? `<button class="link-copy" type="button" data-action="copy" data-record-id="${escapeHtml(record.id)}" data-field="codeUrl">复制链接</button>`
      : '';

    const groupOptions = ['<option value="">未分组</option>', ...state.groups.map((group) => {
      const count = state.records.filter((item) => item.groupId === group.id && item.id !== record.id).length;
      const disabled = count >= MAX_GROUP_SIZE && record.groupId !== group.id;
      return `<option value="${escapeHtml(group.id)}" ${record.groupId === group.id ? 'selected' : ''} ${disabled ? 'disabled' : ''}>${escapeHtml(group.name)} (${count + (record.groupId === group.id ? 1 : 0)}/${MAX_GROUP_SIZE})</option>`;
    })].join('');

    return `
      <article class="record-card ${incomplete ? 'is-incomplete' : 'is-complete'} ${record.isPrimary ? 'is-primary' : ''}" data-record-id="${escapeHtml(record.id)}">
        <details class="record-details" ${editing || state.expandedRecords.has(record.id) ? 'open' : ''}>
          <summary class="record-summary">
            <div class="record-summary-main">
              <h3>${escapeHtml(record.account || '未命名账号')}</h3>
            </div>
            <span class="record-chevron" aria-hidden="true">⌄</span>
          </summary>
          <div class="record-body">
            <div class="record-head">
              <div class="record-identity">
                <button class="status-pill ${incomplete ? 'is-warning' : 'is-ready'}" type="button" data-action="toggle-status" data-record-id="${escapeHtml(record.id)}" data-write ${state.canWrite ? '' : 'disabled'}><i></i>${statusLabel}</button>
                ${editing ? `<label class="group-editor">分组<select class="edit-select" data-edit-field="groupId">${groupOptions}</select></label>` : ''}
              </div>
              <div class="record-actions">
                ${record.groupId ? `<button class="icon-button" type="button" data-action="set-primary" data-record-id="${escapeHtml(record.id)}" data-write ${state.canWrite ? '' : 'disabled'}>${record.isPrimary ? '取消主号' : '设为主号'}</button>` : ''}
                ${record.groupId ? `<button class="icon-button" type="button" data-action="move-up" data-record-id="${escapeHtml(record.id)}" data-write ${memberIndex <= 0 ? 'data-write-blocked' : ''} ${memberIndex <= 0 || !state.canWrite ? 'disabled' : ''}>上移</button><button class="icon-button" type="button" data-action="move-down" data-record-id="${escapeHtml(record.id)}" data-write ${memberIndex < 0 || memberIndex >= groupMembers.length - 1 ? 'data-write-blocked' : ''} ${memberIndex < 0 || memberIndex >= groupMembers.length - 1 || !state.canWrite ? 'disabled' : ''}>下移</button>` : ''}
                <button class="icon-button" type="button" data-action="${editing ? 'save-edit' : 'edit'}" data-record-id="${escapeHtml(record.id)}" data-write ${state.canWrite ? '' : 'disabled'}>${editing ? '保存' : '编辑'}</button>
                ${editing ? `<button class="icon-button" type="button" data-action="cancel-edit" data-record-id="${escapeHtml(record.id)}">取消</button>` : ''}
                <button class="icon-button" type="button" data-action="toggle-password" data-record-id="${escapeHtml(record.id)}" aria-label="${state.revealed.has(record.id) ? '隐藏密码' : '显示密码'}">${state.revealed.has(record.id) ? '隐藏' : '显密'}</button>
                <button class="icon-button is-danger" type="button" data-action="delete" data-record-id="${escapeHtml(record.id)}" data-write aria-label="删除账号" ${state.canWrite ? '' : 'disabled'}>删除</button>
              </div>
            </div>

            <div class="record-grid">
              ${renderCopyField(record, 'account', '账号', record.account, { className: 'field-account' })}
              ${renderCopyField(record, 'password', '密码', record.password, { sensitive: true, className: 'field-password' })}
              ${editing ? renderEditField(record, 'secondaryEmail', '副邮箱', record.secondaryEmail, { type: 'email' }) : renderCopyField(record, 'secondaryEmail', '副邮箱', record.secondaryEmail)}
              ${editing ? renderEditField(record, 'appPassword', '专用密码', record.appPassword) : renderCopyField(record, 'appPassword', '专用密码', record.appPassword, { sensitive: true })}
              ${editing ? renderEditField(record, 'question1', '密保问题 01', record.questions[0]) : renderCopyField(record, 'question1', '密保问题 01', record.questions[0])}
              ${editing ? renderEditField(record, 'question2', '密保问题 02', record.questions[1]) : renderCopyField(record, 'question2', '密保问题 02', record.questions[1])}
              ${editing ? renderEditField(record, 'question3', '密保问题 03', record.questions[2]) : renderCopyField(record, 'question3', '密保问题 03', record.questions[2])}
              ${editing ? renderEditField(record, 'birthDate', '出生日期', record.birthDate, { placeholder: 'YYYY/MM/DD' }) : renderCopyField(record, 'birthDate', '出生日期', record.birthDate)}
              ${editing ? renderEditField(record, 'country', '国家', record.country) : renderCopyField(record, 'country', '国家', record.country)}
              <div class="data-field field-phone"><span class="field-label">手机号</span>${editing ? `<input class="edit-input" type="tel" data-edit-field="phone" value="${escapeHtml(record.phone)}" placeholder="未绑定手机号" />` : phoneMarkup}</div>
              <div class="data-field field-remark"><label class="field-label" for="remark-${escapeHtml(record.id)}">备注</label><input class="remark-input" id="remark-${escapeHtml(record.id)}" type="text" ${editing ? 'data-edit-field="remark"' : 'data-action="update-remark"'} data-record-id="${escapeHtml(record.id)}" value="${escapeHtml(record.remark)}" placeholder="点击填写" aria-label="编辑备注" ${editing || state.canWrite ? '' : 'disabled'} /></div>
            </div>

            <div class="code-strip">
              <div class="code-copy">
                <span class="field-label">短信验证码</span>
                <div class="code-result">${codeStatusMarkup(record)}</div>
              </div>
              <div class="code-meta">
                ${editing ? `<input class="code-url-input" type="url" data-edit-field="codeUrl" value="${escapeHtml(record.codeUrl)}" placeholder="https://取码链接" />` : linkMarkup}
                ${editing ? '' : linkCopyMarkup}
                <button class="refresh-button" type="button" data-action="refresh-code" data-record-id="${escapeHtml(record.id)}" data-write ${record.codeStatus === 'loading' ? 'data-write-blocked' : ''} ${record.codeStatus === 'loading' || !state.canWrite ? 'disabled' : ''}>${record.codeStatus === 'loading' ? '读取中' : '刷新取码'}</button>
                ${record.codeCheckedAt ? `<span class="checked-at">${escapeHtml(formatCheckedAt(record.codeCheckedAt))}</span>` : ''}
              </div>
            </div>
          </div>
        </details>
      </article>`;
  }

  function recordMatches(record) {
    const groupName = state.groups.find((group) => group.id === record.groupId)?.name || '';
    const haystack = [
      record.account,
      record.phone,
      record.secondaryEmail,
      groupName,
      record.country,
      record.birthDate,
      record.remark,
      ...(record.questions || []),
    ].join(' ').toLowerCase();
    const matchesQuery = !state.query || haystack.includes(state.query.toLowerCase());
    const matchesFilter = state.filter === 'all' || record.profileStatus === state.filter;
    return matchesQuery && matchesFilter;
  }

  function render() {
    const completeCount = state.records.filter((record) => record.profileStatus === 'complete').length;
    const incompleteCount = state.records.length - completeCount;
    elements.totalCount.textContent = state.records.length;
    elements.completeCount.textContent = completeCount;
    elements.incompleteCount.textContent = incompleteCount;

    document.querySelectorAll('[data-filter]').forEach((button) => {
      button.classList.toggle('is-active', button.dataset.filter === state.filter);
    });

    const query = state.query.toLowerCase();
    const filtered = state.records.filter(recordMatches);
    const groups = [...state.groups.map((group) => ({ ...group, virtual: false })), { id: '', name: '未分组', virtual: true }];
    const foldersMarkup = groups.map((group) => {
      const records = filtered.filter((record) => record.groupId === group.id).sort((left, right) => left.groupOrder - right.groupOrder || left.account.localeCompare(right.account));
      const showEmptyFolder = !group.virtual && state.filter === 'all' && (!query || group.name.toLowerCase().includes(query));
      if (!records.length && !showEmptyFolder) return '';
      const primary = records.find((record) => record.isPrimary);
      return `<section class="folder-group" data-group-id="${escapeHtml(group.id)}">
        <details class="folder-details" ${state.expandedGroups.has(group.id) || state.query ? 'open' : ''}>
          <summary class="folder-summary">
            <div class="folder-title"><span class="folder-icon">▰</span><strong>${escapeHtml(group.name)}</strong><span>${records.length}${group.virtual ? '' : `/${MAX_GROUP_SIZE}`}</span>${primary ? `<small>主号 · ${escapeHtml(primary.account)}</small>` : ''}</div>
            <div class="folder-actions">${group.virtual ? '' : `<button type="button" data-action="rename-group" data-group-id="${escapeHtml(group.id)}" data-write>改名</button><button type="button" data-action="delete-group" data-group-id="${escapeHtml(group.id)}" data-write>删除组</button>`}<span class="record-chevron">⌄</span></div>
          </summary>
          <div class="folder-records">${records.length ? records.map(renderRecord).join('') : '<div class="folder-empty">这个分组还是空的</div>'}</div>
        </details>
      </section>`;
    }).join('');
    elements.recordsList.innerHTML = foldersMarkup;
    const hasFolders = Boolean(foldersMarkup);
    elements.recordsList.hidden = !hasFolders;
    elements.emptyState.hidden = hasFolders;
    if (!hasFolders) {
      elements.emptyState.innerHTML = state.records.length
        ? '<strong>没有匹配的账号</strong><span>换一个关键词，或切换左侧筛选。</span>'
        : '<strong>档案柜还是空的</strong><span>把账号资料粘贴到上方，解析后就会出现在这里。</span>';
    }
    setWriteAvailability();
  }

  function getRecordCard(id) {
    return [...elements.recordsList.querySelectorAll('.record-card')].find((card) => card.dataset.recordId === id);
  }

  function updatePasswordUI(record) {
    const card = getRecordCard(record.id);
    if (!card) return;
    const revealed = state.revealed.has(record.id);
    card.querySelectorAll('.field-value.is-secret[data-field]').forEach((button) => {
      const value = getFieldValue(record, button.dataset.field);
      const valueText = button.querySelector('span:first-child');
      if (valueText) valueText.textContent = revealed && value ? value : (value ? '••••••••' : '未填写');
    });
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
      refreshButton.toggleAttribute('data-write-blocked', record.codeStatus === 'loading');
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

  function openGroupDialog(groupId = '') {
    const group = state.groups.find((item) => item.id === groupId);
    state.editingGroupId = group?.id || '';
    elements.groupDialogTitle.textContent = group ? '修改分组名称' : '新建分组';
    elements.groupNameInput.value = group?.name || '';
    elements.groupError.textContent = '';
    if (elements.groupDialog.showModal) elements.groupDialog.showModal();
    else elements.groupDialog.setAttribute('open', '');
    window.setTimeout(() => elements.groupNameInput.focus(), 0);
  }

  function closeGroupDialog() {
    state.editingGroupId = '';
    elements.groupForm?.reset();
    elements.groupError.textContent = '';
    if (elements.groupDialog.close) elements.groupDialog.close();
    else elements.groupDialog.removeAttribute('open');
  }

  function handleGroupSubmit(event) {
    event.preventDefault();
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      elements.groupError.textContent = getVaultWriteUnavailableMessage(state.syncStatus);
      return;
    }
    const name = clean(elements.groupNameInput.value).slice(0, 80);
    if (!name) {
      elements.groupError.textContent = '请输入分组名称';
      return;
    }
    const duplicate = state.groups.find((group) => group.id !== state.editingGroupId && group.name.toLocaleLowerCase() === name.toLocaleLowerCase());
    if (duplicate) {
      elements.groupError.textContent = '已经有同名分组';
      return;
    }

    const previousGroups = state.groups;
    const isRename = Boolean(state.editingGroupId);
    const timestamp = new Date().toISOString();
    if (state.editingGroupId) {
      state.groups = state.groups.map((group) => group.id === state.editingGroupId
        ? { ...group, name, updatedAt: nextTimestamp(group.updatedAt) }
        : group);
    } else {
      const group = { id: makeId(), name, updatedAt: timestamp };
      state.groups = [...state.groups, group];
      state.expandedGroups.add(group.id);
    }
    syncSnapshot(state.records, state.deleted, state.clearAt)
      .then(() => {
        closeGroupDialog();
        notify(isRename ? '分组已改名' : '分组已创建', 'success');
      })
      .catch(() => {
        state.groups = previousGroups;
        elements.groupError.textContent = '服务器未确认保存，请重试';
        render();
      });
  }

  function deleteGroup(groupId) {
    const group = state.groups.find((item) => item.id === groupId);
    if (!group) return;
    const memberCount = state.records.filter((record) => record.groupId === groupId).length;
    requestConfirmation(`确定删除分组“${group.name}”吗？其中 ${memberCount} 个账号会回到“未分组”。`, () => {
      if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
        notify(getVaultWriteUnavailableMessage(state.syncStatus), 'warning');
        return;
      }
      const timestamp = nextTimestamp(group.updatedAt);
      const previousGroups = state.groups;
      const previousDeletedGroups = state.deletedGroups;
      state.groups = state.groups.filter((item) => item.id !== groupId);
      state.deletedGroups = { ...state.deletedGroups, [groupId]: timestamp };
      state.expandedGroups.delete(groupId);
      state.expandedGroups.add('');
      const previousRecords = state.records;
      const records = state.records.map((record) => record.groupId === groupId
        ? { ...record, groupId: '', groupOrder: 0, isPrimary: false, updatedAt: nextTimestamp(record.updatedAt) }
        : record);
      state.records = records;
      syncSnapshot(records, state.deleted, state.clearAt)
        .then(() => {
          notify('分组已删除，账号已移到未分组', 'success');
        })
        .catch(() => {
          state.groups = previousGroups;
          state.deletedGroups = previousDeletedGroups;
          if (state.records === records) state.records = previousRecords;
          render();
          notify('服务器未确认删除，分组未改变', 'warning');
        });
    }, '删除这个分组？');
  }

  function saveRecordEdit(recordId) {
    const record = state.records.find((item) => item.id === recordId);
    const card = getRecordCard(recordId);
    if (!record || !card) return;
    const values = Object.fromEntries([...card.querySelectorAll('[data-edit-field]')].map((input) => [
      input.dataset.editField,
      input.dataset.editField === 'appPassword' ? input.value : input.value.trim(),
    ]));
    if (values.secondaryEmail && !/^[^\s@]+@[^\s@]+\.[^\s@]+$/u.test(values.secondaryEmail)) {
      notify('副邮箱格式不正确', 'warning');
      card.querySelector('[data-edit-field="secondaryEmail"]')?.focus();
      return;
    }
    const phoneDigits = asText(values.phone).replace(/\D/g, '');
    if (values.phone && (phoneDigits.length < 7 || phoneDigits.length > 15)) {
      notify('手机号格式不完整', 'warning');
      card.querySelector('[data-edit-field="phone"]')?.focus();
      return;
    }
    if (values.codeUrl && !normalizeCodeUrl(values.codeUrl)) {
      notify('取码链接必须是 http 或 https 地址', 'warning');
      card.querySelector('[data-edit-field="codeUrl"]')?.focus();
      return;
    }
    const groupId = values.groupId === undefined ? record.groupId : clean(values.groupId);
    const group = state.groups.find((item) => item.id === groupId);
    if (groupId && !group) {
      notify('选择的分组已经不存在', 'warning');
      return;
    }
    if (groupId !== record.groupId && groupId && state.records.filter((item) => item.groupId === groupId).length >= MAX_GROUP_SIZE) {
      notify(`“${group.name}”已有 ${MAX_GROUP_SIZE} 个账号`, 'warning');
      return;
    }

    const value = (field) => values[field] ?? getFieldValue(record, field);
    const codeUrl = normalizeCodeUrl(values.codeUrl ?? record.codeUrl);
    const codeUrlChanged = codeUrl !== record.codeUrl;
    const next = {
      ...record,
      questions: [value('question1'), value('question2'), value('question3')],
      birthDate: value('birthDate'),
      country: value('country'),
      phone: value('phone'),
      codeUrl,
      remark: value('remark'),
      secondaryEmail: value('secondaryEmail'),
      appPassword: value('appPassword'),
      groupId,
      groupOrder: groupId === record.groupId ? record.groupOrder : state.records.filter((item) => item.groupId === groupId).length,
      isPrimary: groupId === record.groupId ? record.isPrimary : false,
      ...(codeUrlChanged ? { smsCode: '', codeStatus: 'idle', codeError: '', codeCheckedAt: '' } : {}),
      updatedAt: nextTimestamp(record.updatedAt),
    };
    const records = normalizeVaultLayout(state.records.map((item) => item.id === recordId ? next : item), state.groups);
    const previousRecords = state.records;
    state.records = records;
    syncSnapshot(records, state.deleted, state.clearAt, { renderResult: false })
      .then(() => {
        state.editing.delete(recordId);
        state.expandedRecords.add(recordId);
        render();
        notify('账号资料已保存', 'success');
      })
      .catch(() => {
        if (state.records === records) state.records = previousRecords;
        notify('服务器未确认保存，编辑内容仍保留在页面中', 'warning');
      });
  }

  function updateRecordManagement(recordId, action) {
    const record = state.records.find((item) => item.id === recordId);
    if (!record) return;
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      notify(getVaultWriteUnavailableMessage(state.syncStatus), 'warning');
      return;
    }
    let records = state.records.map((item) => ({ ...item }));
    if (action === 'toggle-status') {
      const target = records.find((item) => item.id === recordId);
      target.profileStatus = target.profileStatus === 'complete' ? 'incomplete' : 'complete';
      target.updatedAt = nextTimestamp(target.updatedAt);
    } else if (action === 'set-primary') {
      records.forEach((item) => {
        if (item.groupId === record.groupId) {
          const nextPrimary = item.id === recordId ? !record.isPrimary : false;
          if (item.isPrimary !== nextPrimary) item.updatedAt = nextTimestamp(item.updatedAt);
          item.isPrimary = nextPrimary;
        }
      });
    } else {
      records = moveRecordWithinGroup(records, recordId, action === 'move-up' ? -1 : 1);
      records.filter((item) => item.groupId === record.groupId).forEach((item) => {
        item.updatedAt = nextTimestamp(item.updatedAt);
      });
    }
    const previousRecords = state.records;
    state.records = records;
    syncSnapshot(records, state.deleted, state.clearAt).catch(() => {
      if (state.records === records) state.records = previousRecords;
      render();
      notify('服务器未确认操作，状态未改变', 'warning');
    });
  }

  async function fetchTextWithTimeout(url) {
    const controller = typeof AbortController === 'function' ? new AbortController() : null;
    const timer = window.setTimeout(() => controller?.abort(), REQUEST_TIMEOUT_MS);
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
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      notify(`${getVaultWriteUnavailableMessage(state.syncStatus)}，暂时不能刷新验证码`, 'warning');
      return;
    }

    const requestedUrl = record.codeUrl;
    record.codeStatus = 'loading';
    record.codeError = '';
    record.codeCheckedAt = new Date().toISOString();
    updateCodeUI(record);

    let smsCode = '';
    let codeStatus = 'blocked';
    let codeError = '';
    try {
      let responseText;
      let lastError;
      for (const requestUrl of getCodeRequestUrls(requestedUrl)) {
        try {
          responseText = await fetchTextWithTimeout(requestUrl);
          break;
        } catch (error) {
          lastError = error;
        }
      }
      if (responseText === undefined) throw lastError || new Error('code request failed');
      smsCode = extractSixDigitCode(responseText);
      codeStatus = smsCode ? 'found' : 'empty';
      notify(smsCode ? '已读取到 6 位验证码' : '链接中没有符合条件的验证码', smsCode ? 'success' : 'info');
    } catch {
      codeError = getCodeFailureMessage(requestedUrl);
      notify(`${codeError}，仍可点击链接查看`, 'warning');
    }
    const latest = state.records.find((item) => item.id === id);
    if (!latest || latest.codeUrl !== requestedUrl) return;
    Object.assign(latest, { smsCode, codeStatus, codeError, codeCheckedAt: new Date().toISOString() });
    touchRecord(latest);
    updateCodeUI(latest);
    try {
      await syncSnapshot(state.records, state.deleted, state.clearAt, { renderResult: false });
      updateCodeUI(state.records.find((item) => item.id === id) || latest);
    } catch {
      updateCodeUI(latest);
    }
  }

  function handleImport() {
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      notify(getVaultWriteUnavailableMessage(state.syncStatus), 'warning');
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

    const previousRecords = state.records;
    const merged = mergeRecords(state.records, result.records);
    const grouped = applyImportedGroups(merged.records, result.records, state.groups);
    const previousGroups = state.groups;
    state.groups = grouped.groups;
    state.records = grouped.records;
    grouped.createdGroupIds.forEach((groupId) => state.expandedGroups.add(groupId));
    if (grouped.records.some((record) => !record.groupId)) state.expandedGroups.add('');
    setFeedback(result, merged.duplicateCount);
    syncSnapshot(grouped.records, state.deleted, state.clearAt)
      .then(() => {
        elements.importInput.value = '';
        notify(`已保存 ${result.records.length} 条账号资料${grouped.overflowCount ? `，${grouped.overflowCount} 条因分组已满保持原位置` : ''}`, grouped.overflowCount ? 'warning' : 'success');

        const importedAccounts = new Set(result.records.filter((record) => record.codeUrl).map((record) => record.account));
        state.records.filter((record) => importedAccounts.has(record.account)).forEach((record) => refreshCode(record.id));
      })
      .catch(() => {
        state.groups = previousGroups;
        if (state.records === grouped.records) state.records = previousRecords;
        notify('服务器未确认保存，资料仍留在输入框中', 'warning');
      });
  }

  function handleExportAll() {
    if (!state.records.length) {
      notify('档案柜里没有可导出的账号', 'warning');
      return;
    }

    const content = formatExportText(state.records, state.groups);
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
      if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
        notify(getVaultWriteUnavailableMessage(state.syncStatus), 'warning');
        return;
      }
      const nextRecords = state.records.filter((item) => item.id !== id);
      const nextDeleted = { ...state.deleted, [record.account]: nextTimestamp(record.updatedAt) };
      const previousRecords = state.records;
      state.records = nextRecords;
      syncSnapshot(nextRecords, nextDeleted, state.clearAt)
        .then(() => {
          state.revealed.delete(id);
          notify('账号已删除', 'success');
        })
        .catch(() => {
          if (state.records === nextRecords) state.records = previousRecords;
          notify('服务器未确认删除，资料未改变', 'warning');
        });
    }, '删除这条档案？');
  }

  function clearAll() {
    if (!state.records.length && !state.groups.length) {
      notify('档案柜已经是空的', 'info');
      return;
    }
    requestConfirmation('确定清空全部账号资料吗？此操作不可恢复。', () => {
      if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
        notify(getVaultWriteUnavailableMessage(state.syncStatus), 'warning');
        return;
      }
      clearServerState()
        .then(() => {
          state.revealed.clear();
          state.editing.clear();
          state.expandedGroups.clear();
          state.expandedRecords.clear();
          notify('全部账号资料已清空', 'success');
        })
        .catch((error) => {
          if (state.syncStatus !== 'auth') setSyncStatus('error', `同步失败 · ${getSyncErrorMessage(error)}`);
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
  elements.createGroupButton?.addEventListener('click', () => openGroupDialog());
  elements.groupForm?.addEventListener('submit', handleGroupSubmit);
  elements.cancelGroupButton?.addEventListener('click', closeGroupDialog);
  elements.groupDialog?.addEventListener('cancel', (event) => {
    event.preventDefault();
    closeGroupDialog();
  });
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
    const { action, recordId, groupId, field } = actionTarget.dataset;
    if (action === 'rename-group') {
      event.preventDefault();
      openGroupDialog(groupId);
      return;
    }
    if (action === 'delete-group') {
      event.preventDefault();
      deleteGroup(groupId);
      return;
    }
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
    } else if (action === 'edit') {
      state.editing.add(recordId);
      state.expandedRecords.add(recordId);
      render();
      getRecordCard(recordId)?.querySelector('[data-edit-field]')?.focus();
    } else if (action === 'cancel-edit') {
      state.editing.delete(recordId);
      render();
    } else if (action === 'save-edit') {
      saveRecordEdit(recordId);
    } else if (['toggle-status', 'set-primary', 'move-up', 'move-down'].includes(action)) {
      updateRecordManagement(recordId, action);
    } else if (action === 'delete') {
      deleteRecord(recordId);
    }
  });

  document.addEventListener('input', (event) => {
    const remarkInput = event.target.closest('[data-action="update-remark"]');
    if (!remarkInput) return;
    const record = state.records.find((item) => item.id === remarkInput.dataset.recordId);
    if (!record) return;
    if (!canQueueVaultWrite(state.syncStatus, state.authHeader, state.serverStateLoaded)) {
      notify(`${getVaultWriteUnavailableMessage(state.syncStatus)}，备注暂不保存`, 'warning');
      return;
    }
    record.remark = remarkInput.value;
    touchRecord(record);
    const records = state.records.map((item) => ({ ...item }));
    window.clearTimeout(state.remarkTimers.get(record.id));
    state.remarkTimers.set(record.id, window.setTimeout(() => {
      syncSnapshot(records, state.deleted, state.clearAt, { renderResult: false })
        .then(() => {
          const input = getRecordCard(record.id)?.querySelector('[data-action="update-remark"]');
          if (input && document.activeElement !== input) input.value = state.records.find((item) => item.id === record.id)?.remark || '';
        })
        .catch(() => notify('服务器未确认备注保存，可点击刷新同步重试', 'warning'));
    }, 350));
  });

  elements.confirmDialog.addEventListener('cancel', () => {
    state.confirmAction = null;
  });

  elements.recordsList.addEventListener('toggle', (event) => {
    if (event.target.matches('.folder-details')) {
      const groupId = event.target.closest('.folder-group')?.dataset.groupId ?? '';
      if (event.target.open) state.expandedGroups.add(groupId);
      else state.expandedGroups.delete(groupId);
    } else if (event.target.matches('.record-details')) {
      const recordId = event.target.closest('.record-card')?.dataset.recordId;
      if (!recordId) return;
      if (event.target.open) state.expandedRecords.add(recordId);
      else state.expandedRecords.delete(recordId);
    }
  }, true);

  render();
  if (state.authHeader) {
    setSyncStatus('loading');
    loadServerState(true);
  } else {
    setSyncStatus('auth');
    showAuthDialog();
  }
})();
