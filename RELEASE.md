# Release Guide

本文定义 IAM 当前基础能力的发布门禁、生产配置合同、回退方式和生产试点验收标准。

## 试点范围

当前可发布范围以 README 的“当前基线能力”和仓库中的可执行代码为准：

- Spring Boot 模块化单体和 GraalVM Native Image；
- PostgreSQL、Flyway 迁移、租户、组织、用户和凭据数据；
- 本地密码认证领域能力、LDAP credential verifier；
- Redis 登录限流和一次性安全状态；
- OAuth 2.0 Authorization Code、PKCE、OpenID Connect、Refresh Token 和 Client Credentials；
- 匿名 SCIM 2.0 discovery、受 scope 保护的资源命名空间、租户隔离的 User 与 Group 生命周期；
- 健康探针、Prometheus 指标、OpenTelemetry 和告警规则。

OAuth 2.0/OIDC、SCIM discovery 以及 Users 和 Groups 生命周期已提供 HTTP 入口并纳入发布门禁。
Admin RBAC、完整 MFA 和审计 HTTP 入口尚未提供，
因此当前试点不得宣称这些外部工作流已经可用。新增 HTTP adapter 后必须补充协议一致性、安全性和
端到端验收。

`compose.yaml` 和 `local` profile 只用于开发与发布验证，不是生产部署清单。

## 自动发布门禁

GitHub Actions 在 pull request、`master` push、手动触发和每周定时任务中运行完整门禁：

```bash
./scripts/verify-release
```

门禁使用 Oracle GraalVM 25.0.3，并执行：

1. Maven `clean verify`，包括完整 JVM 测试和 Flyway 升级测试；
2. Prometheus 告警规则单元测试；
3. GraalVM Native Image 构建；
4. 全新数据库迁移、探针、指标和 schema history 检查；
5. SCIM discovery、租户隔离的 User 与 Group 生命周期、service JWT read/write 边界、OAuth 2.0 Authorization Code、PKCE、OIDC、Refresh Token 和 Client Credentials HTTP smoke；
6. Redis/PostgreSQL 中断、readiness 降级、liveness 保持和恢复；
7. 缺少安全 secret 时的 fail-closed readiness；
8. 重启迁移幂等性和 SIGTERM 优雅关闭。

`--smoke-only` 只用于复用已经构建的本地 Native 可执行文件，不是发布门禁的替代品。仓库管理员应将
`Release verification` 配置为受保护分支的 required status check。workflow 文件本身不能设置分支
保护。

门禁会拉取官方 `latest` 验证镜像并在日志中记录实际 digest。Linux Native 压缩包、SHA-256 文件、
测试报告、Git commit 和 Actions 日志共同构成发布证据。正式部署必须使用通过同一次门禁的制品，不能
在部署阶段重新构建。

## 生产配置合同

每个环境必须显式配置以下内容：

| 类别 | 要求 |
|---|---|
| 应用身份 | 固定 Git commit、应用版本、目标平台和 Native 制品 SHA-256 |
| PostgreSQL | TLS 验证、最小权限运行账号、独立 migrator 账号、备份和高可用 |
| Redis | Redis 6.2+、TLS、认证、受限 key-prefix ACL 和高可用 |
| 环境标签 | `IAM_DEPLOYMENT_ENVIRONMENT` 和 `IAM_SERVICE_NAMESPACE` |
| Authorization issuer | `IAM_AUTHORIZATION_ISSUER`，稳定的环境专用 HTTPS URL |
| Service token audience | `IAM_AUTHORIZATION_SERVICE_TOKEN_AUDIENCE`，稳定的 SCIM resource HTTPS URL |
| SCIM base URL | `IAM_SCIM_BASE_URL`，以 `/scim/v2` 结尾的稳定 HTTPS URL |
| Token 加密 key | `IAM_AUTHORIZATION_TOKEN_ACTIVE_KEY_ID` 和对应的 32 字节 Base64 key |
| Signing key 加密 key | `IAM_AUTHORIZATION_SIGNING_KEY_ACTIVE_KEY_ID` 和对应的独立 32 字节 Base64 key |
| 登录限流 secret | `IAM_LOGIN_RATE_LIMIT_KEY_SECRET`，独立的 32 字节以上 Base64 secret |
| 安全状态 secret | `IAM_SECURITY_STATE_KEY_SECRET`，独立的 32 字节以上 Base64 secret |
| 遥测 | 环境对应的 OTLP endpoint、采样率、指标出口和资源标签 |

上述加密 key 和 HMAC secret 必须由 secret manager 注入，彼此不同，并在同一环境的所有实例、滚动
重启和应用回退期间保持稳定。当前版本尚未提供保护 key 重加密命令，被数据库密文引用的旧 key 必须
保留；不得使用 `application-local.yaml` 中的本地值。

PostgreSQL 运行账号不得拥有创建数据库、超级用户或修改历史 Flyway migration 的权限。生产迁移应由
单一 migrator 使用独立账号执行，成功后再扩容普通应用实例。

签名密钥元数据 attestation 不检测整条历史合法记录的回放。数据库恢复后必须将 active `kid` 与数据库外
的部署记录核对；在引入数据库外的不可回退信任锚之前，不得启用 signing key 在线轮换。

Redis ACL 至少允许应用 key 前缀所需的连接、脚本、`SET` 和 `GETDEL` 操作。验证环境使用官方
`latest` 镜像发现兼容性变化；生产环境应使用通过验收并记录的版本或 digest，不应依赖本地缓存中的
可变标签。

SCIM service JWT 使用离线签名校验，不在每次请求时查询 client 状态。token 声明周期最多 5 分钟，
资源端允许 30 秒验证时钟偏差；考虑签发端与资源端允许的相对时钟偏差，client 或 tenant 被禁用后的
运维处置窗口按最坏约 6 分钟计算。当前版本不提供单 token 即时撤销。

LDAP 默认关闭。启用时必须额外验证 LDAPS 或 StartTLS、证书信任、tenant allowlist、稳定 subject、
目录超时和独立 synthetic probe。LDAP 不属于应用 readiness group。

## 部署与迁移

1. 确认目标 commit 的 `Release verification` 成功，并核对 Native SHA-256。
2. 创建 PostgreSQL 加密备份，记录备份 ID、时间、RPO、RTO 和负责人。
3. 在隔离环境完成备份恢复和当前 migration rehearsal。
4. 停止旧版本写入或进入维护窗口，只运行一个 Flyway migrator。
5. 核对 `flyway_schema_history` 全部成功且数量与发布包中的 `V*.sql` 一致。
6. 部署已验证的同一 Native 制品，等待所有实例 `/readyz` 返回 `200`。
7. 验证 Prometheus 抓取、告警路由、日志/trace 关联和依赖故障恢复。

历史 `V*.sql` 只允许追加，禁止修改已发布 migration。生产不得启用 Flyway clean 或依赖手工反向
DDL。

## 探针与管理端点

`/livez` 只表示进程存活；数据库或 Redis 故障时仍应返回 `200`。`/readyz` 包含数据库、Redis、登录
限流和安全状态，任一必需依赖不可用时应返回 `503`。

当前 `/actuator/**`、`/livez` 和 `/readyz` 没有应用级认证。生产 ingress 必须只允许编排器和
Prometheus 所在的受控网络访问这些路径，或将 management server 放到独立的内部端口；不得直接暴露
到公网。

## 备份与恢复

每次 schema 变更前必须完成可恢复的 PostgreSQL snapshot 或 `pg_dump`，并在隔离数据库执行一次
restore、migrate 和关键数据核对。验收记录至少包含 Flyway history、关键表行数或 checksum、迁移
耗时和锁等待。

Redis 保存限流预算和一次性短期安全状态。不得恢复旧 Redis snapshot，以免复活已经消费的 token。
Redis 丢失后应按空库恢复：现有 challenge 全部失效，限流预算重置；试点必须接受该语义，并在必要时
使用入口侧临时限流。

## 回退

每次发布必须保留上一 Native 制品、配置引用和 secret 引用。

- 如果上一版本已经验证兼容当前 schema，可直接回退应用并重新验证 `/readyz`。
- 如果 schema 不向后兼容，先停止写入，再通过 PITR 或备份恢复数据库，并将旧数据库与旧制品成对恢复。
- 不得通过编辑历史 migration、执行未演练的反向 DDL 或恢复旧 Redis 安全状态完成回退。

回退后必须重新检查租户隔离、本地密码认证、限流、安全状态、探针、指标和告警恢复。

## 生产试点准入

以下条件全部满足后才能进入当前范围的生产试点：

- 目标 commit 的 required check 和完整 release gate 通过；
- Native 制品 SHA-256、镜像 digest、测试报告和 migration 清单已归档；
- 全新安装和上一发布版本升级均通过；
- PostgreSQL 备份恢复与应用回退已在隔离环境演练；
- PostgreSQL/Redis 故障、恢复、重启和优雅停止行为符合门禁；
- 租户隔离、本地密码认证、限流 fail-closed 和一次性状态已验收；
- LDAP 仅在启用时完成安全传输、allowlist 和故障验收；
- Prometheus 抓取、告警接收和恢复通知已实际验证；
- management 端点和探针不存在公网暴露；
- 已明确记录尚未提供的 Admin RBAC、完整 MFA 和审计 HTTP 能力。

告警路由、生产部署清单、真实备份自动化和目标环境协议验收仍由目标环境负责，不能以本地 Compose
或当前 release gate 代替。
