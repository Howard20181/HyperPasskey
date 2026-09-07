# HyperPasskey（修复分支说明 + 推荐应用声明）

本 fork 由 [Howard20181/HyperPasskey](https://github.com/Howard20181/HyperPasskey) 维护增强，修复第三方浏览器在 HyperOS 上无法创建通行密钥（Passkey / WebAuthn）的问题，详见 [PR #28](https://github.com/Howard20181/HyperPasskey/pull/28) 与 [Issue #27](https://github.com/Howard20181/HyperPasskey/issues/27)。

## 功能

解除 GMS（Google 密码管理器）"特权浏览器白名单"对非收录浏览器的拦截：

- 修复前：第三方浏览器创建 WebAuthn 通行密钥报 `[28442] Invalid calling package.`
- 修复后：正常弹出创建界面并可正常使用
- 凭据数据本身仍由 Google 官方流程生成（rpId 绑定 / 加密 / 签名校验均不受影响）

## 推荐应用

以下场景经实测或已知可用：

| 应用/浏览器 | 包名 | 状态 |
|---|---|---|
| Via 浏览器 | `mark.via` | ✅ 已实测（webauthn.io 创建 + 使用成功） |
| 其他第三方浏览器 | — | ✅ 理论全通过（同一放行点，按 origin 正常放行） |
| 特权白名单内浏览器（Chrome 等） | — | ✅ 不受影响，走原逻辑 |

支持场景：任何通过 Android CredentialManager 走 GMS CredentialProvider 的 passkey 请求（GitHub、Google 账号等支持 passkey 的网站在第三方浏览器内均可）。

不适用：App 内部自实现的非 GMS 凭据路径（部分银行/企业 App），这些不经过被 hook 的校验点。

## 环境要求

- HyperOS / Android 14+（实测环境：小米 14 Pro，HyperOS 4.0.0.24，Android 17，GMS 26.32.34）
- GMS 正常登录且 Google 密码管理器可用
- LSPosed（libxposed API），作用域需勾选 `com.google.android.gms`
- 跨 GMS 版本兼容：混淆类名自动通过 DexKit 按字符串特征定位，无需随版本更新

## 许可

沿用上游 LICENSE。
