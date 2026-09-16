# 续签助手

一个仅服务当前 Mac 的 iOS IPA 签名、安装和续签工具。签名与设备操作均在应用内完成，不需要安装或启动 Xcode。

当前版本仅支持 macOS。Windows 会明确显示平台不支持，签名、安装和续签功能不会启用。

## 环境

- macOS 15 或更高版本（Intel 与 Apple Silicon 各有独立安装包，不是 Universal）
- 首次使用时在应用内登录 Apple ID 并完成 2FA
- Keychain 中带私钥的 `Apple Development` 身份
- 已配对、已解锁并开启开发者模式的 iOS 设备
- UUID 匹配的 `980Pro` 卷

芯片架构和这块外置盘是两件独立的事。程序即使是 ARM64 原生编译，未连接 UUID 匹配的 `980Pro` 时仍只显示历史、不会改用内置盘。那不是芯片不兼容。

当前 Intel 安装包可在本机构建。Apple Silicon 安装包必须在 M 芯片 Mac 上原生构建，并完成同一套登录、钥匙串、证书复用、签名和设备安装验收后，才能称为已兼容。仅 ARM64 编译成功不能代替真机验收。

密码和验证码只在登录任务内存中使用；会话令牌和签名私钥保存在 macOS 钥匙串。应用不保存 Cookie，也不会修改系统安全设置。

## 目录

- 托管 IPA：`/Volumes/980Pro/AppData/IPARenewalAssistant`
- 临时缓存：`/Volumes/980Pro/Cache/IPARenewalAssistant`
- 状态文件：`~/Library/Application Support/com.shus.iparenewalassistant/state.json`
- 脱敏审计日志：`~/Library/Application Support/com.shus.iparenewalassistant/audit.jsonl`

980Pro 缺失、身份不符或不可写时，应用只显示已有历史，不会改用内置盘。

## 开发启动

项目侧开发入口会核验 980Pro 卷身份、签名组件、macOS SDK 和 OpenSSL，构建原生签名器，并用 Wails v2.12.0 打开开发界面。不进行全局工具安装，也不要求先生成正式 `.app`。

```bash
./scripts/dev.sh
```

普通构建缓存和临时 IPA 留在 `980Pro`；Apple 会话、私钥和临时钥匙串留在内置盘。任务结束后会清理本次临时敏感材料，不会删除已保存的登录会话。

登录在应用内完成：密码和验证码只在本次登录过程中使用，不会写入状态或审计。多团队账号必须明确选择 `teamID`；签名器严格使用所选团队，并优先复用本机已有私钥的开发证书。仅当开发者账户上还没有开发证书时才会自动申请。账户里已有证书但本机没有匹配私钥时会停止并弹出确认框：可导入含私钥的签名身份，或明确确认后用当前登录账号在这台 Mac 重新签发（会作废现有开发证书）。**不会自动撤销，也不会在未确认时反复申请**。

签名保留原 IPA 和原 Bundle ID。校验在解包后的 `.app` 及实际存在的扩展、嵌套代码上进行，失败时不会覆盖上一次有效产物。安装使用现有 `go-ios` 实现：需要 USB、已配对且开发者模式已开启；未知状态不会视为通过。安装后会回查 Bundle ID/版本并启动应用，成功后才写入安装记录。不会自动卸载手机上的原有应用。

## 开发与验证

```bash
go test ./...
go vet ./...
cd frontend && npm test && npm run build
```

真实设备验收需要显式启用，并提供 IPA 路径与设备选择，不会混入普通测试：

```bash
IPA_RENEWAL_REAL_ACCEPTANCE=1 \
IPA_RENEWAL_ACCEPTANCE_IPA=/path/to/app.ipa \
IPA_RENEWAL_ACCEPTANCE_DEVICE=<设备ID或UDID> \
go test -run TestCurrentIPARealAcceptance -v -count=1
```

密码和验证码请在本机界面输入，不要放到命令或聊天中。

## 构建

开发入口会发现本机架构匹配的 OpenSSL 3，不默认使用 Intel Homebrew 路径 `/usr/local/opt/openssl@3`。也可以显式设置 `OPENSSL_PREFIX`。构建机上的 OpenSSL 只用于编译；正式安装包会带上 `altsign-cli` 和 `libssl`/`libcrypto`，目标机不必安装相同路径的 OpenSSL。

不要只跑 `wails build`。那样得到的 `.app` 没有签名器和 OpenSSL，不能拷到另一台 Mac 使用。开发界面测通也不等于安装包可用。

```bash
./scripts/build-app.sh amd64    # Intel：build/bin/darwin-amd64/续签助手.app
./scripts/build-app.sh arm64    # Apple Silicon：在 M 芯片 Mac 上运行
```

产物目录互不覆盖。每个架构的 zip 在同目录下，例如 `IPARenewalAssistant-v0.1.0-macos-amd64.zip`。两个架构都打好、并在 M 芯片真机完成验收之前，不会发布 GitHub Release。
