# IAM

统一身份管理平台，面向现代应用的认证、授权、用户生命周期管理和安全审计。

IAM 是一个开源的 Identity and Access Management 项目，目标是构建一套可自托管、可扩展、可生产部署的身份基础设施，为业务系统提供统一的账号、登录、应用接入、Token、权限治理、生命周期管理和安全审计能力。

## 项目目标

IAM 的最终目标是成为面向现代应用的统一身份与访问管理核心平台。

项目目标覆盖：

- 多业务系统统一登录
- 本地账号体系
- 企业级 SSO 接入
- OAuth 2.0 / OIDC 应用接入
- API Token 与会话管理
- 用户、管理员、服务账号等主体管理
- 用户生命周期自动化
- SCIM 用户与组同步
- RBAC 权限治理
- ABAC / ReBAC / FGA 策略扩展
- MFA 与高风险操作保护
- 审计日志、安全事件和 SIEM 集成
- 多租户、组织和成员关系管理
- 可观测、可部署、可维护的生产级运行形态

项目长期围绕 IAM 的七个核心维度建设：

| 维度 | 目标 |
|---|---|
| 主体 / 用户 | 管理用户、管理员、服务账号、外部目录用户、租户、组织和成员关系 |
| 凭据与登录 | 支持本地密码、MFA、SSO、外部目录认证和 Passkeys |
| 应用 / 客户端 | 管理 OAuth/OIDC Client、服务客户端、回调地址、scope、audience 和客户端认证方式 |
| Token / 会话 | 管理 JWT、ID Token、Refresh Token、会话、撤销、轮换、logout 和风险响应 |
| 权限 / 授权 | 支持 Admin RBAC、服务 scope、业务角色映射和策略引擎扩展 |
| 生命周期 | 支持账号、凭据、客户端、服务账号、租户、组织、授权关系和访问复核的完整生命周期 |
| 审计 / 安全事件 | 记录认证、授权、生命周期、安全风险、审计查询、导出和告警事件 |

## 项目定位

IAM 关注身份基础设施，不承载具体业务系统。

IAM 负责：

- 识别主体身份
- 校验主体认证状态
- 管理应用接入方式
- 签发和校验 Token
- 管理基础权限和 scope
- 提供用户与账号生命周期能力
- 记录安全审计和风险事件
- 为业务系统提供身份和授权上下文

IAM 不负责：

- 保存具体业务资源
- 直接拥有订单、文档、项目、审批等业务对象
- 将所有业务权限规则硬编码进 IAM Core
- 在没有明确边界前拆成大量微服务
- 通过 SCIM 直接授予最高管理权限

业务资源级授权由业务系统自己的 Access Layer 或外部策略服务承载。IAM 提供主体、角色、scope、组织、租户、审计和策略扩展点。

## 第一阶段目标

第一阶段的目标是把 IAM 打造成清晰、稳定、可生产试点的身份核心服务。

第一阶段交付以下基础闭环：

- 架构边界清晰
- 模块化单体可维护
- 本地账号体系可用
- OAuth 2.0 / OIDC 基础能力可用
- JWT 与 Refresh Token 生命周期可用
- SCIM 基础用户和组同步可用
- Admin RBAC 可用
- 管理员 MFA 可用
- 审计与风险事件可用
- 数据库迁移和部署基础可控
- 具备接入 LDAP、租户、组织和安全运营能力的扩展点

## 第一阶段实施范围

第一阶段重点围绕生产化基础、企业目录接入和多租户基础切片展开。

| 编号 | 任务 | 说明 |
|---|---|---|
| P1-01 | 数据库迁移基线 | 引入 Flyway 或 Liquibase，替代生产环境中的隐式 schema 初始化 |
| P1-02 | 租户与组织基础模型 | 建立 tenant、organization、成员关系和基础隔离模型 |
| P1-03 | LDAP/AD bind 密码验证 | 在已有外部目录查询基础上，支持企业目录密码认证 |
| P1-04 | 外部凭据验证 SPI | 抽象外部 credential verifier，避免认证逻辑和 LDAP 实现强耦合 |
| P1-05 | Redis 分布式限流与临时状态 | 支持多实例部署下的登录限流、MFA challenge、短期安全状态 |
| P1-06 | 生产观测基础 | 完善健康检查、指标、trace、日志关联和基础告警 |
| P1-07 | 发布与验收基线 | 固化测试、迁移验证、部署检查和生产试点验收标准 |

## 第一阶段不包含

以下能力不进入第一阶段，后续按需求逐步实现：

- SAML SSO
- Passkeys / WebAuthn
- 普通用户完整 MFA 策略
- 完整 ABAC / ReBAC / FGA 策略引擎
- 业务资源级 Access Review
- 厂商特定 SIEM schema
- 完整自适应风险引擎
- 大规模微服务拆分

这些能力依赖更稳定的主体、凭据、Token、租户、审计和部署基础。

## 当前基线能力

当前项目已经具备以下基础能力：

- Spring Boot 4.1 模块化单体基础
- PostgreSQL 与 Flyway schema 管理
- 租户领域模型、受保护的内置默认租户和事务化生命周期操作
- 租户隔离的组织模型、JDBC 持久化和乐观并发控制
- 租户隔离的用户目录、统一登录标识和事务化生命周期操作
- 用户软删除标识保留、乐观并发收敛和租户写入保护
- 租户隔离的用户资料、目录组和直接用户组成员关系
- OAuth 2.0 Authorization Code、PKCE、OpenID Connect、Refresh Token 和 Client Credentials
- 租户绑定的机器客户端、短期 SCIM audience JWT 和可信 `tenant_id` claim
- SCIM Users/Groups 资源命名空间的专用 JWT profile 校验与 `scim.read` / `scim.write` 授权边界
- SCIM 2.0 ServiceProviderConfig、Schemas 和 ResourceTypes discovery
- 租户隔离的 SCIM User 单资源读取、属性选择和统一的资源不可见响应
- 租户隔离的 SCIM Group 单资源与集合读取、direct User 成员引用和统一的资源不可见响应
- 有界的 SCIM Users 集合分页，以及 `id`、`userName` 精确查询
- 有界的 SCIM Groups 集合分页，以及 `id`、`displayName` 精确查询
- 租户隔离的 SCIM User 创建、受限可写属性和不泄露标识的唯一性冲突响应
- 租户隔离的 SCIM Group 创建、完整替换与原子局部修改，以及规范的 direct User 成员关系
- 租户隔离的 SCIM Group 软删除、成员关系清理和统一的资源不可见响应
- 租户隔离的 SCIM User 完整替换、原子局部修改与软删除，以及标识更新和内部锁定状态保护
- Actuator 健康检查、Prometheus 指标和 OpenTelemetry tracing
- 接入本地密码登录的 Redis 原子限流、隐私保护键空间和多实例共享计数
- Redis 一次性安全状态、租户与用途绑定、原子消费和自动过期
- GraalVM Native Image 构建与启动验证
- JUnit、Spring Boot Test 和 Testcontainers 测试基线

## 技术栈

IAM 当前采用 Java 与 Spring 生态构建，已引入的核心技术栈如下：

| 类别 | 技术 |
|---|---|
| 编程语言 | Java 21 |
| 应用框架 | Spring Boot 4.1 |
| 模块化架构 | Spring Modulith |
| Web API | Spring MVC |
| 数据访问 | Spring JDBC / JdbcClient |
| 数据库 | PostgreSQL |
| 数据库迁移 | Flyway |
| 配置管理 | Spring Boot Configuration Properties / Environment Variables |
| 观测 | Spring Boot Actuator、Micrometer、Prometheus、OpenTelemetry |
| 本地开发 | Maven Wrapper、Docker Compose |
| 测试 | JUnit 5、Spring Boot Test、Testcontainers、Mockito |
| 构建 | Maven |
| Native 构建 | Oracle GraalVM 25 |

第一阶段新增或强化的技术组件：

| 类别 | 技术方向 |
|---|---|
| 数据库迁移 | Flyway |
| 分布式临时状态 | Redis |
| 企业目录认证 | LDAP / Active Directory bind |
| 外部凭据校验 | Credential verifier SPI |
| 生产观测 | OpenTelemetry Collector、Prometheus、Grafana、告警规则 |

## 架构方向

IAM 当前采用模块化单体架构。

选择模块化单体是为了：

- 降低部署复杂度
- 保持事务和数据一致性简单
- 让早期模型更容易演进
- 通过模块边界保持代码可维护
- 为后续必要的服务拆分保留空间

只有当某个模块出现明确的独立扩展、独立部署、独立数据所有权或故障隔离需求时，才拆分为独立服务。

核心模块方向：

| 模块 | 职责 |
|---|---|
| `auth` | 登录、OAuth 2.0、OIDC、SSO 交互 |
| `admin` | 管理员认证、RBAC、Access Review、高风险确认 |
| `user` | 用户目录、用户生命周期、外部目录查询扩展 |
| `credential` | 密码、TOTP、恢复码、密钥加密 |
| `client` | OAuth/OIDC 应用客户端管理 |
| `serviceaccount` | 服务账号、机器身份与服务客户端凭据 |
| `token` | Access Token、ID Token、Refresh Token、风险事件 |
| `session` | 用户、管理员和服务会话 |
| `scim` | SCIM 用户和组同步 |
| `audit` | 审计日志、安全事件查询和导出 |
| `policy` | ABAC / ReBAC / FGA 策略扩展点 |
| `security` | Spring Security 与 JWT 校验 |
| `ratelimit` | 登录限速 |
| `securitystate` | MFA challenge 与一次性短期安全状态 |
| `config` | 类型化运行配置 |

## 设计原则

项目遵循以下原则：

- 标准协议优先
- 安全默认值优先
- 模块边界清晰
- 单体优先，必要时再拆分
- 本地账号可独立运行
- 企业目录作为可插拔能力
- Token 与 Session 生命周期可审计
- 管理面操作可追踪
- 高风险操作具备二次确认能力
- 业务资源事实不进入 IAM Core
- 扩展点优先于提前实现复杂规则

## API 范围

标准协议接口：

```text
/oauth2/**
/.well-known/**
/userinfo
/connect/logout
```

SCIM 接口：

```text
GET /scim/v2/ServiceProviderConfig
GET /scim/v2/Schemas
GET /scim/v2/Schemas/{id}
GET /scim/v2/ResourceTypes
GET /scim/v2/ResourceTypes/{id}
GET /scim/v2/Users
GET /scim/v2/Users/{id}
POST /scim/v2/Users
PUT /scim/v2/Users/{id}
PATCH /scim/v2/Users/{id}
DELETE /scim/v2/Users/{id}
GET /scim/v2/Groups
GET /scim/v2/Groups/{id}
POST /scim/v2/Groups
PUT /scim/v2/Groups/{id}
PATCH /scim/v2/Groups/{id}
DELETE /scim/v2/Groups/{id}
```

discovery 接口匿名开放。Users 和 Groups 读取使用带 `scim.read` scope 的机器 token，资源写入使用
`scim.write`，并且只从已验证的 `tenant_id` claim 确定租户。集合查询支持 `startIndex`、`count`，
以及未在 discovery 中宣告为通用 filtering 能力的精确查询：Users 支持 `id eq`、`userName eq`，
Groups 支持 `id eq`、`displayName eq`。所有返回资源的操作均支持 `attributes`、
`excludedAttributes`。每个 Group 最多包含 1000 个 direct User members，超限数据不会被截断返回。

创建和完整替换 User 时 `userName` 和唯一的 core User schema URN 必填；写操作支持 `displayName`、`name.formatted`、
`name.givenName`、`name.familyName`、单个 `emails.value`、单个 `phoneNumbers.value` 和 `active`。
POST/PUT 中的 `id`、`meta`、`groups` 按 read-only 规则忽略；PATCH 修改 `schemas`、`id`、`meta`、
`groups` 或删除必填 `userName` 时返回固定 `mutability`，未发布路径和值返回不回显输入的协议错误。
PUT 会清空请求中省略的可选资料和登录标识；省略或设置 `active: null` 时保留当前状态，显式
`active: false` 不会把内部 `LOCKED` 状态降级。登录标识或 active 状态发生变化时，现有用户会话失效；
仅资料变化不影响会话。PATCH 支持按序执行 `add`、`remove`、`replace`，支持无 path 属性对象、core
User URN 路径以及 `emails.value`、`phoneNumbers.value` 的过滤 add/remove/replace；filtered add 使用请求中的
`value`，不会用 filter selector 覆盖登录标识。任一操作失败时全部回滚。领域状态
不能表示未赋值的 `active`，因此 discovery 将其发布为必有属性，PATCH 不允许删除或赋 null。email 或
phone 形式的 `userName` 与对应的 `emails` 或 `phoneNumbers` 值是同一登录标识；修改 linked value 会同步
`userName`，删除 primary alias 或用不同 secondary value 覆盖它会被拒绝。SCIM POST、PUT 和 PATCH 请求体
限制为 128 KiB。DELETE 使用 `scim.write`，成功时返回空的 `204 No Content`；删除后资源不可见，但出于
账号接管防护，原有 `userName`、email 和 phone 登录标识保持保留，不能立即用于创建新用户。

Groups 读取返回 direct User members 的 `value`、`type: User` 和 canonical `$ref`，并支持
`attributes`、`excludedAttributes`。创建和完整替换 Group 时 `displayName` 和唯一的 core Group schema
URN 必填；`members` 可省略，每项必须引用当前租户内未删除的 User。PUT 不创建缺失资源，并将省略、
`null` 或空数组的 `members` 解释为空成员集。Group profile 与成员关系在单一事务中更新，一次实际替换
只推进一次 Group directory revision；重复引用按规范化 User ID 去重，失败时不会留下 Group、membership
或 User directory revision 的部分变更。
Group PATCH 按请求顺序原子执行 `add`、`remove` 和 `replace`，支持无 path 属性对象、`displayName`、
完整 `members` 集合以及 `members[value eq "User UUID"]` 选择。删除不存在的成员是成功的 no-op；过滤
replace 未命中时返回固定 `noTarget`。成员子属性不可单独修改，任一操作或成员校验失败时全部回滚。
DELETE 使用 `scim.write`，成功时返回空的 `204 No Content`；Group 被软删除，direct User memberships
被清理，受影响 User 的 directory revision 同步推进，之后的读取、修改和重复删除均返回 `404`。
部署必须通过 `IAM_SCIM_BASE_URL` 提供客户端可访问的 canonical SCIM base URL。

IAM 管理与自服务接口：

```text
/iam/sso/**
/iam/account/**
/iam/admin/**
/iam/audit/**
```

## 运行

使用本地 profile 启动应用，Spring Boot 会读取根目录的 Compose 配置：

```bash
./mvnw spring-boot:run -Dspring-boot.run.profiles=local
```

## 配置

默认配置位于 `src/main/resources/application.yaml`，本地开发覆盖位于
`src/main/resources/application-local.yaml`。生产环境应通过标准 Spring Boot 配置来源提供
数据库连接和 OTLP exporter 配置。

### 可观测性

应用在主端口提供 `/livez` 和 `/readyz`，Prometheus 指标统一包含 `application` 与
`environment` 标签。生产环境通过 `IAM_DEPLOYMENT_ENVIRONMENT` 和
`IAM_SERVICE_NAMESPACE` 设置部署环境与 OpenTelemetry service namespace；默认 trace 采样率为
10%，`local` profile 为 100%。

基础 Prometheus 告警规则位于 `observability/prometheus/iam-alerts.yaml`。规则假定 scrape job 名为
`iam-core-service`，生产部署应将该文件加载到 Prometheus 或兼容 ruler，并根据实际流量调整阈值和
告警路由。应用指标按 `environment` 分组；全局 target 缺失规则无法推断多环境中的单环境目标清单，
集中式 ruler 需要额外维护按环境的预期目标规则。本地 LGTM 只用于开发和验证，不作为生产告警平台。

使用 `grafana/otel-lgtm:latest` 内置的 `promtool` 校验规则及其单元测试：

```bash
docker run --rm \
  --entrypoint /otel-lgtm/prometheus/promtool \
  --workdir /rules \
  -v "$PWD/observability/prometheus:/rules:ro" \
  grafana/otel-lgtm:latest \
  test rules iam-alerts.test.yaml
```

### LDAP 外部凭据

LDAP provider 默认关闭。启用时必须配置独立的 provider ID、允许使用该目录的 tenant、
安全目录地址以及只读查询账号。生产连接仅接受 LDAPS 或 StartTLS。

`iam.credential.external.ldap.subject-attribute` 必须是目录保证全局唯一、不可变且不会分配给
其他账号的稳定标识。标准 LDAP 默认使用 `entryUUID`；Active Directory 可配合
`BINARY_BASE64URL` 使用 `objectGUID`。不要使用登录名、邮箱、员工编号或 DN 作为 subject。

目录查询和用户 bind 必须在数据库事务之外执行。验证指标只包含 provider 与结果状态，
不包含 tenant、登录值、DN、subject 或密码。

### 登录限流

登录尝试通过 Redis 同时限制 tenant + principal 和 tenant + source。source 必须由可信入口在处理
代理链后提供规范化的不透明标识，不能直接信任客户端提交的 `X-Forwarded-For`。

生产环境必须通过 `IAM_LOGIN_RATE_LIMIT_KEY_SECRET` 为所有实例提供同一份至少 32 字节的
Base64 secret。该 secret 用于 HMAC-SHA256 键派生，Redis key 不包含原始 tenant、登录值或来源值。
`local` profile 提供的默认值只用于本地开发。

可通过 `iam.ratelimit.login.principal-limit`、`principal-window`、`source-limit` 和
`source-window` 调整固定窗口。Redis 不可用或 secret 缺失时限流返回 `UNAVAILABLE` 并拒绝继续
认证；不得降级为放行或普通凭据失败。限流获取与成功后的 principal 计数清理必须在数据库事务
之外执行，成功清理不会重置 source 预算。成功清理使用一次性 lease；较早成功的请求不能清除
在其之后到达的尝试。

本地密码登录结果区分 `AUTHENTICATED`、通用凭据拒绝 `REJECTED`、带重试时间的 `THROTTLED` 和
依赖故障 `UNAVAILABLE`。只有认证事务提交成功后才清理 principal 计数；调用方不得在已有数据库
事务中发起登录。

生产 Redis 必须位于受保护网络中，启用传输加密与认证，并为应用账号配置满足脚本执行和键操作
所需的最小权限 ACL。HMAC 只避免在 key 中暴露原始标识，不能替代 Redis 的访问控制、传输保护、
高可用和备份策略。

### 一次性安全状态

MFA challenge 和高风险确认等短期流程使用 tenant、purpose 和内部 opaque binding 绑定的一次性
token。token 为 256-bit 随机 bearer secret；Redis key 通过 HMAC-SHA256 派生，value 只保存版本
标记，不保存任意 payload、登录标识或联系方式。缺失、过期、重放和绑定不匹配统一返回
`REJECTED`，Redis 或配置不可用返回 `UNAVAILABLE`。

生产环境必须通过 `IAM_SECURITY_STATE_KEY_SECRET` 为所有实例提供同一份独立的至少 32 字节
Base64 secret。`iam.security-state.maximum-ttl` 默认限制为 15 分钟，且不得配置超过 24 小时。
签发使用原子 `SET NX` 与 TTL，消费使用原子 `GETDEL`；两者都不得在数据库事务中调用。生产
Redis 必须为 6.2 或更高版本，应用 ACL 至少允许受限 key 前缀上的 `SET` 和 `GETDEL`。

同一 binding 可同时存在多个相互独立的 token，以支持多设备或多标签页流程；调用方必须限制签发
频率和并发数量。消费采用 at-most-once 语义：`GETDEL` 成功后如果响应丢失或后续受保护操作失败，
必须重新签发 challenge，不得恢复或重复使用原 token。

### Authorization Server issuer 与签名密钥

Authorization Server 使用固定 issuer。`local` profile 默认使用 `http://127.0.0.1:8080`；其他 profile
缺少 `IAM_AUTHORIZATION_ISSUER` 时会拒绝启动。每个生产环境必须配置稳定的 HTTPS URL，issuer 一旦用于
签发 token 就不能随主机名、代理请求头或单次部署变化。

Client Credentials access token 使用 `IAM_AUTHORIZATION_SERVICE_TOKEN_AUDIENCE` 配置稳定的 HTTPS
resource audience。机器 token 的 `tenant_id` 只从持久化 client owner 映射读取，不接受 token 请求中的
tenant 或 audience 参数覆盖；service client 不支持浏览器 redirect、OIDC scope 或 Refresh Token。
SCIM resource server 还会校验固定 issuer、RS256 签名、单一 audience、token 时间窗口、canonical tenant
UUID、合法 client identifier 以及 `sub == client_id`。已签发 JWT 不执行在线撤销查询；token 声明周期
最多 5 分钟，并允许 30 秒验证时钟偏差。考虑签发端与资源端允许的相对时钟偏差，禁用 client 后的
运维处置窗口按最坏约 6 分钟计算。

获得 `iam.admin` scope 的 Authorization Code 或 Refresh Token access token 使用
`IAM_AUTHORIZATION_ADMIN_TOKEN_AUDIENCE` 配置独立的 Admin resource audience。该 token 绑定 tenant、
User、登录 session、认证方式和认证时间；普通 OIDC access token 不包含 Admin audience。Admin resource
server 会在线校验 session 当前可用并从 RBAC 数据实时解析权限，不能把 token 中的 scope 当作管理权限。
`/iam/admin/**` 使用独立的无状态 Bearer security chain；只有显式声明精确 permission 的路由可访问，
其余路径默认拒绝。

首次启动会在 PostgreSQL 中并发安全地创建一把 RSA-3072 active signing key。`kid` 使用 RFC 7638
thumbprint，私钥以 PKCS#8 编码并由独立的 AES-256-GCM key ring 加密，数据库不保存明文私钥。生产环境
必须配置 `IAM_AUTHORIZATION_SIGNING_KEY_ACTIVE_KEY_ID` 和对应的
`IAM_AUTHORIZATION_SIGNING_KEY_V1` 32 字节 Base64 key；所有实例和滚动重启必须共享相同配置。

签名密钥元数据 attestation 会拒绝字段篡改和伪造记录，但不能检测整条历史合法记录的回放。当前版本尚未
提供 signing key 在线轮换或保护 key 重加密命令，因此数据库引用的旧保护 key 必须保留。schema 已预留
`staged`、`active`、`retired` 生命周期，但运行时当前只加载 active key；不要通过手工 SQL 轮换或删除
key。未来加入轮换前，必须同时引入数据库外的不可回退信任锚。`application-local.yaml` 中的固定值仅用于
本地开发。

## 测试

运行完整测试：

```bash
./mvnw test
```

使用 Oracle GraalVM 25 构建 Native Image：

```bash
export JAVA_HOME=/path/to/graalvm-jdk-25
export GRAALVM_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

./mvnw -DskipTests -Pnative native:compile
```

运行完整发布门禁（需要 Docker、Docker Compose 和 Oracle GraalVM 25.0.3）：

```bash
export JAVA_HOME=/path/to/graalvm-jdk-25
export GRAALVM_HOME="$JAVA_HOME"
export PATH="$JAVA_HOME/bin:$PATH"

./scripts/verify-release
```

发布配置、备份恢复、回退和生产试点准入要求见 [`RELEASE.md`](RELEASE.md)。

## 路线图

第一阶段之后，项目继续推进：

- SAML SSO
- 普通用户 MFA
- Passkeys / WebAuthn
- LDAP/AD 完整目录同步
- 业务资源级授权适配
- ABAC / ReBAC / FGA 策略适配
- 业务资源级 Access Review
- 厂商 SIEM schema
- 告警路由
- 完整自适应风险引擎
- 更完整的生产部署方案

## 贡献方向

欢迎围绕以下方向贡献：

- 协议兼容性
- 安全加固
- 测试覆盖
- 数据库迁移
- 外部目录集成
- 租户与组织模型
- 授权策略扩展
- 审计与安全运营
- 开发体验
- 文档完善

贡献时请优先考虑：

- 变更是否符合项目定位
- 变更是否保持模块边界
- 变更是否引入过早复杂度
- 变更是否影响安全默认值
- 变更是否包含测试
- 变更是否改变公开 API 或配置语义

## 安全

如果你发现安全问题，请不要直接公开披露漏洞细节。

正式安全报告流程后续会补充。

## 许可证

本项目采用 Apache License 2.0。
