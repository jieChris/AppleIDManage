# Account Groups and Editing Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 为共享档案柜增加最多 6 人的文件夹分组、组内排序与主号、账号邮箱及资料编辑，并支持导出任意选中账号；登录密码保持只读。

**Architecture:** 扩展现有单行 AES-GCM 加密状态，不增加数据库表。浏览器负责交互预检，Python 存储层负责最终合并、旧客户端兼容和分组约束收敛；所有写入继续复用 `/vault/sync`。

**Tech Stack:** 原生 HTML/CSS/JavaScript、Python 3.12、SQLite、AES-GCM、Nginx、Docker。

---

### Task 1: 扩展服务器加密状态

**Files:**
- Modify: `test_vault_api.py`
- Modify: `vault_api.py`

- [ ] **Step 1: 先写失败测试**

覆盖新增字段往返、分组删除水印、每组第 7 个账号退回未分组、两个主号收敛为一个，以及 `schemaVersion: 1` 写入保留当前扩展字段。

- [ ] **Step 2: 验证 RED**

Run: `python3 -m unittest -v test_vault_api.py`

Expected: 新断言因响应缺少 `groups`、记录缺少扩展字段或 `sync` 签名不支持 schema version 而失败。

- [ ] **Step 3: 最小实现**

在 `normalize_record` 增加 `secondaryEmail/appPassword/profileStatus/groupId/groupOrder/isPrimary`；新增 `normalize_group`、`normalize_deleted_groups` 和分组约束整理函数。把 payload 扩展为 `records/deleted/clearAt/groups/deletedGroups`，并让 handler 将 `schemaVersion` 传给 store。

- [ ] **Step 4: 验证 GREEN**

Run: `python3 -m unittest -v test_vault_api.py && python3 vault_api.py --self-test`

Expected: 全部通过，self-test 输出 `vault api self-check: ok`。

### Task 2: 增加浏览器数据模型和纯函数

**Files:**
- Modify: `app.js`

- [ ] **Step 1: 先增加失败的自检断言**

断言旧账号默认状态、分组排序、6 人上限、主号唯一、导出元数据往返和重复导入保留不可编辑字段。

- [ ] **Step 2: 验证 RED**

Run: `node app.js`

Expected: 因分组 helper 或扩展字段不存在而失败。

- [ ] **Step 3: 实现最小纯函数**

扩展 `normalizeRecord/normalizeServerState/formatRecordForExport/parseImport/mergeRecords`，新增 `normalizeGroup`、`normalizeVaultLayout`、`moveRecordWithinGroup` 和导入分组映射；`syncSnapshot` 发送 `schemaVersion: 2`、`groups`、`deletedGroups`。

- [ ] **Step 4: 验证 GREEN**

Run: `node --check app.js && node app.js`

Expected: 语法通过并输出 `parser self-check: ok`。

### Task 3: 文件夹列表与紧凑编辑 UI

**Files:**
- Modify: `index.html`
- Modify: `app.js`
- Modify: `styles.css`

- [ ] **Step 1: 添加页面骨架**

在档案工具栏加入“新建分组”和“导出选中”，账号摘要加入原生复选框，增加复用的新建/改名分组 dialog；脚本缓存版本递增。

- [ ] **Step 2: 渲染文件夹和账号操作**

把 `render()` 改为“实际分组 + 未分组”区块；分组头提供改名/删除，账号提供状态、主号、上移/下移、编辑，所有写操作沿用 `syncSnapshot` 队列。

- [ ] **Step 3: 实现原位编辑**

编辑态保持登录密码为复制按钮，账号邮箱及其余资料为输入框；保存时校验邮箱、重复账号、HTTP(S) 取码链接和目标组容量。账号改名同时提交旧邮箱删除水印，成功后更新时间并同步，失败保持编辑态。

- [ ] **Step 4: 保持三行信息网格**

桌面端维持四列：账号/密码/副邮箱/专用密码，三道密保/出生日期，国家/手机号/双格备注。状态使用绿色或黄色整列背景和边线；窄屏再降为两列/一列。

- [ ] **Step 5: 本地静态检查**

Run: `git diff --check && node --check app.js && node app.js`

Expected: 全部通过。

### Task 4: 部署与回归

**Files:**
- Modify: `Dockerfile.vault-api` only if runtime packaging requires it
- Deploy: Visa `/root/appleid-vault`

- [ ] **Step 1: 构建并验证后端镜像**

在 Visa 上以新标签构建 API 镜像，先用临时数据库运行 health/state/sync 测试，再切换 `appleid-api`，不得覆盖生产数据库或密钥。

- [ ] **Step 2: 发布静态文件**

上传 `app.js/index.html/styles.css`，核对远端与本地 SHA-256 以及新缓存版本。

- [ ] **Step 3: 仅用 Codex 内置浏览器回归**

验证门禁、8 条旧账号、创建分组、移动 6 条、第 7 条阻止、设置主号、排序、编辑并刷新、绿色/黄色样式、导出、验证码和控制台错误；测试产生的数据在完成后恢复或删除。

- [ ] **Step 4: 最终检查并发布 GitHub**

Run: `python3 -m unittest -v test_vault_api.py && node --check app.js && node app.js && git diff --check`

Expected: 全部通过。提交功能代码并推送 `main`，线上版本与 GitHub 一致。

## Route Deviation

项目没有 `.trellis` 规范树，因此使用仓库既有 `docs/superpowers` 工作流。部署时若 Visa 缺少本地测试依赖，只允许在项目 Docker 镜像内执行测试，不跳过测试。
