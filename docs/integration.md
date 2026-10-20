# 接入指南

本指南面向独立身份前端、保密 Web/BFF 和资源服务的接入者，说明跨请求的流程及约束。接口字段、请求编码、响应和错误以对应构建的 OpenAPI 为准。

## 接入前提

身份前端负责 IAM 登录与账号交互，由接入方提供。它与 IAM 接口使用同一固定 HTTPS origin；入口代理可使用经过证书链及主机名验证的 HTTPS 回源，或在受保护内网使用显式受信的 HTTP 回源。入口清除并重设外来转发头，不开放跨源凭据访问。

`IAM_PROTOCOL_ISSUER` 是固定 HTTPS 根地址，可带端口和末尾 `/`，不支持路径前缀；`IAM_PROTOCOL_IDENTITY_FRONTEND_URI` 是与 issuer 同源且不含查询串或片段的前端地址，可包含路径。不要根据请求 Host 或参数选择 issuer、Token、JWKS 或身份前端。

应用接入前，由管理员登记资源、角色、用户绑定、保密客户端及精确 HTTPS 回调。客户端秘密和资源校验秘密分别保管，仅提供给对应服务端。

## HTTPS 与受信代理

默认由 IAM 提供 HTTPS，忽略转发头。由 Nginx、网关或 WAF 终止 TLS 时，可继续使用经过验证的 HTTPS 回源，也可在受保护内网使用 HTTP 回源。HTTP 回源设置：

```bash
export SERVER_SSL_ENABLED=false
export SERVER_FORWARD_HEADERS_STRATEGY=NATIVE
export SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES='127\.0\.0\.1'
```

`internal-proxies` 是匹配实际代理来源 IP 的正则；上例仅适用于代理与 IAM 通过同一主机的回环地址通信。跨主机或容器部署须替换为 IAM 实际看到的代理地址，限定网络访问，并在入口清除、重设转发头。不能留空、使用通配全部来源的表达式，或信任客户端自报的代理链。

Nginx 的最小 HTTP 回源示例，域名和证书路径按部署环境替换；身份前端的静态资源路由由接入方配置：

```nginx
server {
    listen 443 ssl;
    server_name iam.example.com;
    ssl_certificate /etc/nginx/tls/iam.crt;
    ssl_certificate_key /etc/nginx/tls/iam.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host iam.example.com;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Port "";
        proxy_set_header X-Forwarded-Prefix "";
        proxy_set_header X-Forwarded-Ssl "";
    }
}
```

IAM 仅还原受信连接的 HTTPS 状态和来源 IP，不使用转发 Host 或端口选择应用地址。多级代理须逐跳配置来源信任，避免把客户端输入当作真实地址；来源地址影响尝试预算和审计。浏览器仍使用同源 HTTPS，Cookie 的 Secure、HttpOnly 与 CSRF 要求保持不变。

## 身份前端

### 登录与退出

浏览器使用 `credentials: 'same-origin'` 调用接口：

1. 从 `GET /api/csrf` 取得本会话的 CSRF 值及请求头名。
2. 以 JSON 调用 `POST /login`，由 JavaScript 处理 HTTP 状态和响应。
3. 登录成功后重新获取 CSRF；通过 `GET /api/me` 查询当前用户。
4. 使用当前 CSRF 调用 `POST /logout`，结束当前 IAM 会话。

Cookie `__Host-IAMSESSION` 使用 Secure、HttpOnly、Path=/ 和 SameSite=Lax。不要读取、复制 Cookie，或将 IAM 会话当作业务 API 的 Bearer Token。写操作使用 POST，不能由 GET 触发；其他接口按规范选择 JSON 或表单编码。

入口不得记录请求体、Cookie、Authorization 或秘密响应。页面配置适当的 CSP、禁止嵌入和 `no-referrer`，避免第三方脚本接触凭据；敏感输入在发送后清空，不进入 URL、日志、埋点、错误上报或浏览器持久存储。

### 用户开通与密码操作

组织核验本人后，由管理员签发一次性开通凭据，通过既有可信渠道交付。前端以秘密输入接收凭据，由本人设置密码；不使用带凭据的链接，也不替用户设置密码。完成 `POST /api/account-setup/complete` 后通过正常登录建立会话。

本人修改密码需要当前密码与有效会话。成功后旧会话失效，前端清理本地认证状态并要求正常登录；不能把修改成功当作新登录会话。

密码恢复采用独立的一次性凭据。完成 `POST /api/password-recovery/complete` 会更新密码并撤销旧 IAM 会话；前端清除秘密并要求正常登录，不自动建立认证状态。组织核验及交付操作见 [运维指南](operations.md#密码恢复交付)。

凭据过期、已消费或响应不明时，核查当前状态，由管理员按需取消或重新签发，不重放旧凭据。

### 因素与恢复码

注册因素时，按接口返回的因素标识继续确认或取消，未验证的新因素不表示绑定完成。处理过期和取消结果，不把开始注册显示为认证成功。

更换按接口返回的因素及证明完成新因素验证；旧凭据不能用于重放已完成操作。保存失败不回滚已提交更换，用新因素登录后按正常受保护流程重新生成恢复码，不能查询秘密原文。

恢复因素使用独立的单次证明，并验证新因素后完成。恢复码、开始恢复或完成普通因素恢复都不授予管理员会话。逐步处理过期、取消和已消费结果，不自动重放证明。

恢复码只在签发或重新生成时展示，不能用作管理员 MFA 的动态码。因素密钥与恢复码使用专门区域短期展示，用户保存后隐藏，离开页面或会话结束时清空，不进入日志、URL 或浏览器持久存储。

### 管理员交互

管理前端在有效密码会话上通过 `POST /admin/mfa` 验证管理员 TOTP，并重新取得轮换后的 CSRF。普通用户 TOTP、恢复码和应用角色都不等于 IAM 管理资格。

每次敏感写操作请求本次新动态码，明确展示目标及影响，提交期间防止重复操作。动态码不能自动复用于下一次写入。版本冲突时刷新服务器状态并重新确认，不自动覆盖；隐藏按钮不能代替后端授权。

## 保密 Web/BFF

从固定 issuer 的 Discovery 获取协议元数据，限制为预期 issuer、RS256 和可信 JWKS。Token 内携带的取钥地址不能改变信任来源；客户端只使用元数据实际声明的端点。

BFF 保存客户端秘密，使用 `client_secret_basic`、授权码和 S256 PKCE，并将 state、nonce 及 verifier 绑定到单次登录交易：

1. BFF 发起授权请求，IAM 导航到已配置的独立身份前端。
2. 前端接收短期 `interaction` 句柄，取入内存后立即以 `history.replaceState` 清理 URL，不把原 URL 发给统计或错误收集服务。
3. 查询 `/api/authorization-interactions/{handle}`，展示服务器确认的应用、当前身份及范围；需要登录时先完成 IAM 登录，再重新查询。
4. 用户明确继续或取消后，携带当前 CSRF 提交决定，只导航到服务器成功响应中的 HTTPS 地址，不自行拼接客户端回调。
5. BFF 核对 state、nonce、PKCE 及 Token 签名，单次消费交易；UserInfo 的 subject 与已验证的 ID Token 必须相同。

Access Token 和 Refresh Token 只保留在 BFF 服务端，浏览器持有应用自己的安全会话 Cookie。刷新需要单次消费父凭据；提交后超时或丢失响应时结束本地授权并重新登录，不能盲目重试父 Refresh Token。

## 退出与撤销

| 操作 | 作用范围 |
| --- | --- |
| 应用退出 | 由接入应用结束本地会话，不自动退出 IAM 或其他应用 |
| IAM 退出 | 结束当前 IAM 浏览器会话；应用本地会话及授权分别处理 |

接入应用处理失效 Token，不能仅凭本地 Cookie 继续放行业务操作。当前接入使用身份接口，不假定存在未声明的 RP 发起退出端点。
