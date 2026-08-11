# Apple ID 账号管理器 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use `executing-plans` to implement this plan task-by-task.

**Goal:** 构建一个无需构建工具的本地网页，用于粘贴解析 Apple ID 账号资料、保存搜索、单击复制，并读取手机号取码链接中的 6 位验证码。

**Architecture:** 使用三个静态文件。`app.js` 同时承载纯函数解析器、localStorage 存储和浏览器事件逻辑，初始化只在存在 DOM 时执行，因此可直接用 Node 运行自检。账号数据以账号字符串为唯一键，导入时合并更新；取码请求使用原生 `fetch`，将成功、无验证码和 CORS/网络失败分开显示。

**Tech Stack:** HTML、CSS、原生 JavaScript、localStorage、Clipboard API、Fetch API；无框架、无第三方依赖。

---

### Task 1: 建立解析器、取码提取器和本地数据层

**Files:**
- Create: `/Users/a19/Documents/ChatGPT/AppleIDManage/app.js`
- Test: `node /Users/a19/Documents/ChatGPT/AppleIDManage/app.js`

- [ ] **Step 1: 先写可运行的纯函数自检**

在 `app.js` 顶部先定义并导出/保留以下纯函数接口，然后添加自检调用：

```js
parseImport(text)                 // { records, errors }
parseAccountLine(line)            // 7 字段对象或 { error }
parseContactLine(line)            // { phone, codeUrl } 或 null
extractSixDigitCode(text)         // string | ''
isIncomplete(record)              // boolean
```

自检至少覆盖：

```js
const dash = parseImport(
  'a@example.com----pass----Q1----Q2----Q3----1984/2/25----美国\n+18178668072|https://example.com/code'
);
console.assert(dash.records[0].account === 'a@example.com');
console.assert(dash.records[0].phone === '+18178668072');
console.assert(dash.records[0].codeUrl === 'https://example.com/code');

const spaced = parseImport(
  'b@example.com  pass  Q one  Q two  Q three  1984/2/25  美国'
);
console.assert(spaced.records.length === 1);

console.assert(extractSixDigitCode('验证码：483921') === '483921');
console.assert(extractSixDigitCode('时间 12:34:56，日期 2026-08-11') === '');
console.assert(extractSixDigitCode('request id 1234567890') === '');
```

运行 `node app.js`，预期自检失败，因为函数尚未实现；错误只允许来自断言，不允许出现语法错误。

- [ ] **Step 2: 实现最小解析规则**

先用 `line.split(/\s*-{2,}\s*|\t+|\s{2,}/)` 识别连续短横线、Tab 和连续空格；若不足 7 段，再用带空格的单短横线 `/\s+-\s+/` 识别 `账号 - 密码` 形式，避免切断密码内部没有空格的连字符。少于 7 段返回错误，多于 7 段将多余内容重新合并到国家字段。逐行扫描时，若下一行包含 `|` 且前半段像手机号，就将其作为当前账号的 `phone` 与 `codeUrl`，否则保留为错误行。URL 只接受 `http:` 或 `https:`。

- [ ] **Step 3: 实现不会误认时间的验证码提取**

先匹配“验证码 / OTP / code / verification code”附近的独立 6 位数字；没有上下文时，只接受两侧不是数字、冒号、斜线或短横线的 6 位数字，并拒绝更长数字串。对 `HHMMSS`、`YYYYMMDD`、`YYYYMMDDHHMMSS` 等可判定的时间/日期候选做额外排除；没有候选返回空字符串。

- [ ] **Step 4: 实现 localStorage 数据层**

使用固定 key `apple-id-vault-records`，提供 `loadRecords()`、`saveRecords(records)`、`mergeRecords(existing, parsed)`。读取 JSON 失败时回退为空列表并返回提示，不覆盖导入文本；每条记录生成 `id`、保存 `updatedAt`、默认 `codeStatus: 'idle'`。按 `account` 去重，重复项由新资料覆盖旧资料。

- [ ] **Step 5: 运行自检并提交**

运行 `node app.js`，预期输出 `parser self-check: ok` 且退出码为 0；再运行 `node --check app.js`。提交：

```bash
git add app.js
git commit -m "feat: add account parser and local store"
```

### Task 2: 搭建可访问的页面骨架

**Files:**
- Create: `/Users/a19/Documents/ChatGPT/AppleIDManage/index.html`

- [ ] **Step 1: 写页面结构**

包含以下稳定的 DOM hook，供 `app.js` 事件委托使用：

```html
<textarea id="importInput"></textarea>
<button id="parseButton"></button>
<button id="clearAllButton"></button>
<input id="searchInput" />
<button data-filter="all"></button>
<button data-filter="incomplete"></button>
<div id="importFeedback"></div>
<div id="recordsList"></div>
<div id="emptyState"></div>
<span id="totalCount"></span>
<span id="completeCount"></span>
<span id="incompleteCount"></span>
```

每个记录卡片的字段按钮使用 `data-action="copy"` 与 `data-field`，敏感密码使用 `data-action="toggle-password"`，验证码使用 `data-action="refresh-code"`；链接使用 `target="_blank"`、`rel="noreferrer"`。文本、状态和按钮均提供中文可读标签与键盘焦点。

- [ ] **Step 2: 加入示例和隐私提示**

导入面板内放入一条短横线格式示例和一条 `手机号|URL` 示例；顶部和导入区明确显示“仅保存在此浏览器，不会上传”，并说明取码接口需要 CORS 才能被网页自动读取。

- [ ] **Step 3: 提交页面骨架**

运行 `node --check app.js`（页面尚未连接行为不报错），提交：

```bash
git add index.html
git commit -m "feat: add account manager page shell"
```

### Task 3: 实现档案柜视觉和响应式布局

**Files:**
- Create: `/Users/a19/Documents/ChatGPT/AppleIDManage/styles.css`

- [ ] **Step 1: 建立主题变量与基础排版**

使用石墨黑背景、暖白内容卡、荧光黄绿操作色、琥珀色警告色；标题使用有个性的显示字体栈，数据使用等宽字体栈。用 CSS 变量统一颜色、圆角、阴影和间距，避免引入 CSS 框架。

- [ ] **Step 2: 实现桌面布局**

页面使用 `grid-template-columns` 划分左侧统计栏和右侧内容区；导入面板、搜索栏和记录卡片形成明显层级。卡片中的账号、手机号、验证码使用较大的可点击值，密码默认以圆点遮罩；成功复制和加载状态使用短 CSS 动效。

- [ ] **Step 3: 实现小屏适配和可访问状态**

在 `max-width: 760px` 时将侧栏改为横向统计、内容改为单列；为按钮提供 `:focus-visible`、`:hover` 和禁用状态；保持文本对比度和触控区域至少 44px。

- [ ] **Step 4: 提交样式**

运行 `node --check app.js`，提交：

```bash
git add styles.css
git commit -m "feat: add vault dashboard styling"
```

### Task 4: 连接 UI、复制交互与取码请求

**Files:**
- Modify: `/Users/a19/Documents/ChatGPT/AppleIDManage/app.js`

- [ ] **Step 1: 实现渲染和过滤**

加载记录后渲染统计数字与记录卡片；搜索同时匹配账号、手机号、国家和密保问题；全部/待检查筛选使用同一份 records，不复制数据数组。空列表显示导入提示。

- [ ] **Step 2: 实现导入预览与合并**

点击解析按钮时先显示合法条数、失败行号、重复账号数；有合法记录才写入 localStorage。导入后清空输入框并渲染新列表，同时对带 `codeUrl` 的记录启动一次 `refreshCode(record.id)`。

- [ ] **Step 3: 实现字段复制和密码显示**

用事件委托读取 `data-field`，调用 `navigator.clipboard.writeText(value)`；不可用时使用临时 `textarea` 降级，并将结果写入统一 toast。账号、手机号、三个问题、出生日期、国家和验证码都可复制；密码只复制真实值，不把遮罩文本写入剪贴板。

- [ ] **Step 4: 实现取码状态**

`refreshCode(id)` 设置 `loading` 并保存，然后用 `fetch(codeUrl, { signal: AbortSignal.timeout(8000) })` 读取文本；成功解析设置 `found` 或 `empty`，异常设置 `blocked`。渲染为“读取中… / 6 位验证码 / 无验证码 / 无法读取”，并显示上次检查时间。卡片按钮可以手动重试；不在每次 render 中重复 fetch。

- [ ] **Step 5: 实现删除、清空和刷新持久化**

删除单条记录前确认；清空全部前二次确认；每次变更都保存并重新渲染。页面首次载入从 localStorage 恢复记录，确保刷新后数据仍在。

- [ ] **Step 6: 提交行为层**

运行 `node app.js`、`node --check app.js`，提交：

```bash
git add app.js
git commit -m "feat: wire account manager interactions"
```

### Task 5: 完成内置浏览器验收

**Files:**
- Verify: `/Users/a19/Documents/ChatGPT/AppleIDManage/index.html`
- Verify: `/Users/a19/Documents/ChatGPT/AppleIDManage/app.js`
- Verify: `/Users/a19/Documents/ChatGPT/AppleIDManage/styles.css`

- [ ] **Step 1: 启动本地静态服务器**

在仓库目录执行 `python3 -m http.server 4173`，只供 Codex 内置浏览器访问 `http://127.0.0.1:4173/`；不启动或连接任何外部浏览器。

- [ ] **Step 2: 验证主流程**

粘贴一条账号行和一条手机号取码行，确认解析预览、导入、卡片渲染、手机号显示、链接打开入口、复制反馈、密码显示/隐藏、搜索和删除。

- [ ] **Step 3: 验证边界**

分别验证：连续空格分隔、缺字段、重复账号更新、含日期时间的取码响应、无验证码、无 CORS/网络失败、刷新页面恢复数据、清空二次确认。

- [ ] **Step 4: 收尾检查**

运行 `git status --short` 确认只包含预期文件，运行 `node app.js` 与 `node --check app.js`；视觉检查桌面和窄屏布局后再汇报结果。

## Plan self-review

- Spec coverage: 解析、手机号/URL、验证码、时间排除、localStorage、搜索、复制、删除、响应式、CORS 提示和自检分别覆盖在 Tasks 1–5。
- Placeholder scan: 无 TBD、TODO、FIXME 或空泛“自行处理”步骤。
- Type consistency: `parseImport`、`parseAccountLine`、`parseContactLine`、`extractSixDigitCode`、`isIncomplete`、`refreshCode` 和记录字段名在所有任务中一致。
- Route Deviation: 无；纯静态方案与 CORS ceiling 保持不变。
