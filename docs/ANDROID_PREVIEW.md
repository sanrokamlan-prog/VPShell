# Android Preview 契约

当前工作树已包含 Tauri Android 壳、共享 Rust 策略契约和隔离的移动 IPC。`src-tauri/src/android_preview.rs` 是生命周期与能力策略，`android_native_transport.rs` 直接使用 `ssh2`/libssh2，`android_mobile.rs` 管理原生会话、终端和 Keystore 不透明引用；三者均不调用系统 `ssh`。

## 首版范围

`AndroidPreviewManifest` 使用 schema v1，固定使用 `NativeRustSshSftp` 引擎，并把能力逐项列出。当前允许主机连接、终端、SFTP 和凭据 vault；同步协调器、广播、外部编辑、常驻监控和后台长连接明确关闭。能力清单必须包含九项且不能重复，最多八个会话，后台长连接标志永远不能被打开。

`AndroidHostRequest` 是结构化请求，只接受 UUID 会话 ID、无控制字符且非路径的主机名、`1..=65535` 端口、5--60 秒超时、固定 SHA-256 host-key、受限用户名和不透明的 `ssh-<UUID>`/`key-<UUID>` 引用。密码、私钥和原始 credential 值不进入该模型，也没有 `Debug`/日志出口供它们泄露。

## 生命周期

`AndroidPreviewRuntime` 只允许活动窗口且已解锁时建立会话或执行支持的操作。Tauri 原生窗口失焦与 WebView 后台通知都会增加 generation 并清空原生会话，迟到的连接和 host-key 结果会因 generation/预留状态变化而丢弃；这仍需真机验证 Activity 暂停、进程回收和网络切换。

## 原生 SSH/SFTP 边界

`AndroidNativeConnectionConfig` 要求 5--60 秒超时和固定 `SHA256:<base64>` host-key 指纹。预检只返回候选指纹，用户确认后连接仍在新握手中重新固定校验；认证只接受清零的密码或内存私钥。每会话最多一个前端终端，尺寸为 20--500 列、5--300 行，单次输入/输出最多 64 KiB。SFTP 列表只接受有界绝对路径，最多返回 1,000 项，按类型标记符号链接/特殊条目而不跟随它们；当前移动 UI 尚不支持上传或下载。

Android capability 与桌面 capability 按平台互斥。移动壳只获得 17 个 `android_*` command（其中同步仅为 value-free 状态读取），不获得桌面 PTY、广播、外部编辑、监控、dialog、updater 或 process 权限，也不授予 WebView 直接调用 biometric 插件的 permission。密码、OpenSSH 私钥和私钥口令通过只反序列化、不序列化/调试的请求写入 Android Keystore-backed store，业务 SQLite 只保存不透明引用。manifest 只有 `INTERNET` 权限，禁止 backup/cleartext/FileProvider，Activity 使用 `FLAG_SECURE`。

设置中可选启用 `tauri-plugin-biometric` 2.3.2 的系统生物识别访问门，并允许设备凭据回退；插件当前 Android 实现使用 `BIOMETRIC_WEAK`，因此不得描述为强生物识别保证。启用和关闭都必须由 Rust 直接完成一次系统认证，开关随后存入 Keystore-backed 固定条目。Activity 暂停时先隐藏 WebView，Rust runtime 初始也为 `Locked`；只有 `android_unlock` 认证成功才能进入 `Foreground`，host-key 网络预检和凭据增删也受同一授权。限定 `http://tauri.localhost`（开发时另含固定 localhost 端口）、主 frame、32-byte 上限的 AndroidX WebMessage listener只处理 `show`/`hide`/`failed`，不能解锁 Rust，不使用通用 `addJavascriptInterface`，也不传凭据。WebView 同时禁用长按选择、autofill/content capture、file/content access 和地理位置。此处是应用访问门，不声称 Keystore 中每个密文都由生物识别密钥逐次解密。

该 transport 是桌面现有 `ssh2`/libssh2 兼容路径的移动隔离层。Linux VPS 已完成 `aarch64-linux-android` Rust/NDK 链接并由 Gradle 生成 debug APK/AAB；这证明构建链，不证明真实 OpenSSH 服务器、Android Keystore 运行时、断网/超时或 SFTP 权限兼容。

## 当前缺口

Linux VPS 没有 Android emulator/arm64 真机。同步协调器只接入只读状态，触屏/软键盘适配、SFTP 内容传输、显式复制体验、网络切换/休眠、BiometricPrompt 与 Keystore 运行时均未验收。现有包使用 Android Debug 自签名证书，不是发布物；在这些门槛通过前不得将 Android Preview 标为可发布产品。
