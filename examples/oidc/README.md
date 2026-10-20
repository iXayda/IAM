# IAM 应用接入示例

独立 Node.js 22 工程。使用 `openid-client` 完成保密 Web/BFF 的 OIDC 登录，使用 `jose` 验证资源 Access Token。同一 BFF 用不同配置运行两个应用；每个应用具有独立客户端秘密、HTTPS origin 和本地会话。资源服务的在线校验秘密与 BFF 的客户端秘密分别保存。

## 运行前提

需要可用的 IAM 协议服务、同源独立身份前端、已开通用户和可注册应用的管理员。IAM 安装与协议接入见 [项目 README](../../README.md)及 [接入指南](../../docs/integration.md)。本目录的进程是业务应用示例，身份前端由接入方提供。

以下命令均在 `examples/oidc/` 目录执行。先安装依赖：

```bash
npm ci --ignore-scripts
```

## 注册应用

由管理员通过独立身份前端调用 IAM 管理接口，先创建资源及角色、为用户绑定角色，再注册关联资源的保密客户端。每次敏感写操作均需要本次新 TOTP。接口的字段、版本、请求类型及错误由 IAM Swagger 描述。

| 配置 | 应用 A | 应用 B |
| --- | --- | --- |
| BFF origin | `https://127.0.0.2:9444` | `https://127.0.0.3:9445` |
| 精确回调 | `https://127.0.0.2:9444/callback` | `https://127.0.0.3:9445/callback` |
| 资源 audience 示例 | `orders-a` | `orders-b` |
| 资源 API origin | `https://127.0.0.4:9446` | `https://127.0.0.5:9447` |
| 允许 scope | `openid profile offline_access` | `openid profile offline_access` |

客户端 ID 使用创建响应中的 `client.id`；秘密仅创建或轮换时返回一次。角色来自相应资源及客户端允许集，不能授予 IAM 管理权限。

每个资源单独调用校验凭据轮换接口，取得只供该资源服务端使用的秘密。`API_VALIDATION_CLIENT_ID` 使用资源 UUID，`API_VALIDATION_CLIENT_SECRET` 使用此次返回的秘密；查询不能取回原文。该身份只能内省本资源的 Token，不能兑换授权码或刷新。

## 配置与运行

复制 `.env.example` 为受保护的 `.env.rp-a` 和 `.env.rp-b`，分别填写实际 UUID、秘密、资源及 TLS 文件。`RP_NAME` 分别为 `a`、`b`，`IAM_ISSUER` 与 IAM 的 `IAM_PROTOCOL_ISSUER` 完全一致，`IAM_IDENTITY_FRONTEND_URI` 指向同源的独立身份前端。不要将秘密、保护文件或本地环境文件提交到 Git。

证书须包含对应域名或 IP，浏览器也需信任开发 CA。使用开发 CA 时，在每个终端启动 Node 前设置 `NODE_EXTRA_CA_CERTS`；`--env-file` 不会加载该证书：

```bash
export NODE_EXTRA_CA_CERTS=/absolute/path/development-ca.pem
```

保留证书链及主机名检查，分别在四个终端启动：

```bash
node --env-file=.env.rp-a api.mjs
node --env-file=.env.rp-b api.mjs
node --env-file=.env.rp-a rp.mjs
node --env-file=.env.rp-b rp.mjs
```

## 体验登录与退出

打开应用 A，点击登录，在 IAM 独立身份前端完成密码认证并确认目标应用与范围。随后在同一浏览器登录应用 B，复用 IAM 会话完成 SSO。BFF 使用 Discovery、授权码、S256 PKCE、state 和 nonce，限定固定 issuer、RS256 及其 JWKS；登录交易在代码兑换前单次消费。UserInfo 的 subject 必须与已验证的 ID Token 相同。

成功登录轮换应用 Cookie 与 CSRF；Cookie 使用 `__Host-`、Secure、HttpOnly、SameSite=Lax。Access Token、Refresh Token 仅保留在 BFF 内存，浏览器没有这些 Token；ID Token 完成校验后不保留。页面及浏览器持久存储不保存协议凭据。

点击“续期应用访问”演示刷新。并发请求共享一次刷新，发送前移除父 Refresh Token；超时、响应丢失或返回无效时销毁本地授权并要求重新登录，禁止重试已提交的父凭据。刷新不能扩大 scope、改变 subject 或原始 `auth_time`，也不延长本地会话绝对期限。

点击“退出此应用”结束该 BFF 本地会话；IAM 会话、其他应用及应用授权分别管理。通过链接进入独立身份前端执行 IAM 退出或授权撤销。本示例不依赖未发布的 RP 发起退出协议端点。

## 资源授权

`GET /orders` 需要 `reader`；`POST /orders` 需要 `editor`，仅演示接收，不持久化订单。角色可以通过 `API_READ_ROLE` / `API_WRITE_ROLE` 配置。资源逐请求验证固定 issuer、RS256、可信 JWKS、`typ=at+jwt`、单个 audience 和期限，拒绝 Token 自带的取钥地址及作为 API 凭据的 ID Token。

验签后，资源使用独立 Basic 凭据调用 `/oauth2/introspect`，将返回的主体、客户端、audience、时间、scope 和角色与 JWT 绑定。正缓存最多 5 秒且不超过 Token 精确到期时间；`API_POSITIVE_CACHE_SECONDS=0` 每次查询。已知依赖故障清除正缓存，在途旧响应不能重新填入；故障或缓存到期时拒绝操作。发现故障前的有效缓存属于既定撤销窗口，不使用过期缓存或自动离线放行。

此示例选择在线校验。其他资源若明确选择纯离线模式，300 秒 Token 和最多 30 秒时钟偏差可能保留 330 秒撤销窗口，失陷密钥还需独立紧急更新与拒绝。真实业务系统应在服务端补齐具体操作和对象所有权检查；这里的固定订单数据不代表对象授权实现。

## 会话边界

进程内存储有容量及绝对期限，重启需要重新登录。多实例接入须使用共享存储并保持登录交易单次消费及刷新协调语义；本示例不能直接用作多实例会话存储。

## 验证

```bash
npm test
npm run check
```

测试覆盖请求与配置边界、刷新并发及丢失响应，以及真实 RSA 签名 Token 的在线缓存和用途隔离。完整互操作验证见 [浏览器验证入口](../../tests/browser/README.md)，它运行本示例的实际 BFF 与资源进程。

依据：[openid-client 官方示例](https://github.com/panva/openid-client/blob/main/examples/oidc.ts)、[OIDC Core](https://openid.net/specs/openid-connect-core-1_0.html)、[RFC 7662](https://www.rfc-editor.org/rfc/rfc7662)、[RFC 8725](https://www.rfc-editor.org/rfc/rfc8725)。
