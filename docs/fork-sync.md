# Fork 合并上游保护与同步指南（`smime` 分支）

本仓库为 [godwit-email/godwit](https://github.com/godwit-email/godwit) 的衍生 Fork，默认开发与发版分支为 `smime`。日常维护通过 `.github/workflows/sync-upstream.yml` 每天定时巡检上游 `main`：
- 无冲突时，自动推送 `sync/upstream-main` 并创建/更新同步 PR；
- 有冲突时，中止合并（不破坏 `smime`），创建或更新追踪 Issue 列出上游提交与冲突文件清单，再按下方规则在本地（或由 Agent）解冲突并验证。

## 1. 严格禁止事项：SQLite Schema 版本对齐

- **绝不要在 `core/store/schema.go` 的 `Migrations` 切片末尾追加 Fork 专属表或字段**。
  - 上游每次发布新迁移都会占用下一个 `PRAGMA user_version` 槽位；若 Fork 抢先占用了该槽位，老用户升级后会导致 `user_version` 跳过上游新增的列/表，或后续合并出现静默漏迁移。
- **Fork 专属的表或兼容补丁**必须放在以下两处之一：
  1. `core/store/store.go` 中的 `DB.ensureForkSchema(ctx)`（在 `Migrations` 循环之后幂等执行）；
  2. 懒建表函数（如 `core/smime_certs.go` 中的 `ensureSMIMETables`）。

## 2. 冲突文件三类处理规则

### A 类：始终保留我方（`smime`）配置与归属
- `.github/workflows/release.yml`、`.github/workflows/homebrew.yml`、`.github/workflows/sync-upstream.yml`（防止被上游 `release-please` 工作流覆盖）
- `mygo.config.ts`：版本号可跟随上游更新（保留 `env.GODWIT_BUILD_VERSION || "<version>"`），**必须保留** `updates`（`publicKey` 与 `github: "jhzhang09/godwit"`）及 `resources: ["LICENSE", "NOTICE"]`
- `LICENSE`、`NOTICE`、`README.md`（保留 Fork 说明与归属，必要时合入上游安全文档提示）

### B 类：自动生成或结构化文件（合并后重生成）
- `uiclient/client_gen.go`、`web/src/mygo.ts`、`internal/i18n/catalog_gen.go`、`web/src/i18n.ts`：解完 Go/i18n 冲突后统一运行 `go tool mygo generate` 重新生成
- `internal/i18n/*.json`：合并 JSON 键值，同时保留上游新文案与 Fork 专属键（如 `smime.*`），并用 `python3 -c 'import glob,json;[json.load(open(p)) for p in glob.glob("internal/i18n/*.json")]'` 校验语法
- `rpcbind/testdata/*.txt`：保留双方方法清单，并确保 `go test ./rpcbind` 通过
- `go.mod` / `go.sum`：接纳上游依赖升级并保留 Fork 依赖，必要时执行 `go mod tidy`

### C 类：核心业务代码（语义融合 + 测试兜底）
以下高频重叠文件必须结合上下文语义融合，不能简单选边覆盖：
- `core/compose.go`、`core/drafts_extra.go`、`webui/compose.go`、`web/src/compose/*`：同时保留上游新增字段/排版规则（如定时草稿、签名在引用上方）与 Fork 的原格式/内嵌图片/S/MIME 解密正文引用与签名加密面板
- `core/attachments.go`、`core/messages.go`、`core/smime_fetch.go`：保留上游新能力（如 `CachedAttachments`、`msgInJunk`）以及 Fork 的内嵌图片后台预取、直连复用与多关键词搜索
- `app/app.go`、`app/reader.go`、`app/reader_smime.go`：保留上游附件下载/拖出等改进，同时保留 Fork 的 S/MIME 阅读解密、最近搜索记录与读信顶部防空白/防抖动修复
- `core/mail/sanitize.go`：保留上游样式白名单放宽与 `JoinDraft` 规则，同时保留 Fork 引用清洗辅助函数

## 3. 标准本地合并与验证流程

```sh
git remote get-url upstream >/dev/null 2>&1 || git remote add upstream https://github.com/godwit-email/godwit.git
git fetch upstream main
git merge upstream/main
```

解决冲突并运行代码生成与验证：

```sh
go tool mygo generate
go test ./core/store -count=1
go test -race ./core -run "TestSMIME|TestInline|TestGetMessage|TestSearch|TestFind|TestReply|TestForward|TestDraft|TestCachedAttachments|TestSavedView" -count=1
go test ./app -run "TestHighlight|TestSearch|TestPalette|TestReader|TestDownload" -count=1
go test ./rpcbind ./webui -count=1
cd web && bun run typecheck && bun run test
```
