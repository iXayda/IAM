# IAM

简体中文 | [English](README.en.md)

IAM 是面向单个组织、多个自有应用的身份与访问管理项目，让各应用共用账号和登录体系，集中管理用户、应用角色、会话和安全审计。

项目提供 IAM 后端；登录与管理交互由独立身份前端实现，业务应用通过 OIDC 接入，并管理自己的页面和应用会话。

## 适用场景

- 多个自有应用需要统一账号和单点登录。
- 需要集中管理用户开通、停用、密码恢复及应用访问权限。
- 需要统一查询和撤销会话，并追踪关键安全操作。

IAM 负责账号、身份认证和应用级授权；业务对象及具体业务操作的权限由接入应用执行。

## 开发与运行

项目使用 Spring Boot 4.1.1、Java 21 和 PostgreSQL 18。构建需要 JDK 21，使用仓库中的 Maven Wrapper；集成测试通过 Docker 启动隔离的 PostgreSQL 容器，需要可用的 Docker。

执行测试并构建可执行 JAR：

```bash
./mvnw clean verify
```

启动应用前配置专用 PostgreSQL 数据库连接及 HTTPS 入口：

| 环境变量 | 内容 |
| --- | --- |
| `SPRING_DATASOURCE_URL` | PostgreSQL JDBC 连接地址 |
| `SPRING_DATASOURCE_USERNAME` | 数据库用户名 |
| `SPRING_DATASOURCE_PASSWORD` | 数据库密码，由运行环境注入 |
| `SERVER_SSL_ENABLED` | IAM 提供 HTTPS 时为 `true`；受信代理通过 HTTP 回源时为 `false` |
| `SERVER_SSL_KEY_STORE` | IAM 提供 HTTPS 时必填，TLS 密钥库位置，例如 `file:/run/secrets/iam.p12` |
| `SERVER_SSL_KEY_STORE_PASSWORD` | IAM 提供 HTTPS 时必填，密钥库密码，由运行环境注入 |
| `SERVER_FORWARD_HEADERS_STRATEGY` | 默认 `NONE`；受信代理模式使用 `NATIVE` |
| `SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES` | `NATIVE` 模式必填，匹配实际代理来源 IP 的正则 |
| `IAM_TOTP_KEY_FILE` | 启用 TOTP 功能时必填，指向包含 32 个原始二进制字节的外部保护密钥文件 |
| `IAM_SIGNING_KEY_FILE` | 签名私钥的保护密钥文件，包含 32 个原始二进制字节，须与 TOTP 使用不同的密钥 |
| `IAM_PROTOCOL_ISSUER` | 启用协议入口时必填，显式配置 IAM 的 HTTPS 根地址（可带端口和末尾 `/`），不从请求 Host 或代理头推导 |
| `IAM_PROTOCOL_IDENTITY_FRONTEND_URI` | 启用浏览器授权导航时必填，与 issuer 同源的固定 HTTPS 身份前端地址，不含查询串或片段 |
| `IAM_AUTHORIZATION_KEY_FILE` | 启用协议入口时必填，指向包含 64 个原始二进制字节的独立授权状态保护文件；与签名及 TOTP 保护密钥分别保管 |

使用专用 IAM 数据库，并分别配置数据库所有者和受限运行账号。迁移、管理员初始化与部署维护使用所有者连接；Web 服务使用运行账号。两组凭据分别注入，运行进程不持有维护密码。保护密钥需要持久保存并限制读取权限，不应提交到仓库或在每次启动时重新生成。

数据库管理员在受控 `psql` 会话中创建独立角色和数据库，使用 `\password` 交互设置密码：

```sql
CREATE ROLE iam_owner LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password iam_owner
CREATE ROLE iam_runtime LOGIN NOINHERIT NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
\password iam_runtime
CREATE DATABASE iam OWNER iam_owner;
```

在维护环境注入 `iam_owner` 的 JDBC 连接，配置持久签名和 TOTP 保护文件，依次迁移、初始化签名身份和管理员。命令独立运行，不监听 HTTP：

```bash
java -jar target/iam.jar migrate
java -jar target/iam.jar initialize-signing-key
java -jar target/iam.jar bootstrap-admin
```

管理员初始化前，由组织授权人员核验本人，安排账号本人在受控的真实交互终端执行。按提示创建账号或选择已有活动账号，验证密码并完成 TOTP 绑定与验证。密码和动态码无回显输入，不接受附加参数或管道输入；不录屏或采集终端输出，安全保存一次性展示的恢复码。初始化仅允许完成一次，中断后可继续，完成后不能重复获取资格或恢复码。

使用数据库所有者的 `psql` 连接应用权限清单。通过受保护的密码文件或部署秘密管理提供凭据；以下命令采用已配置的 `PGHOST`、`PGPORT`、`PGDATABASE` 和 `PGUSER`：

```bash
psql -X --set=runtime_role=iam_runtime --set=iam_schema=public --file=deploy/postgresql/grant-runtime.sql
```

清单显式授予业务所需权限，新增表不自动授权。运行账号不能建表、执行迁移、删改审计记录、变更管理员资格或签名密钥，也不能拥有对象或具备提权能力。默认使用 `public` schema；自定义 schema 和升级步骤见 [数据库安装与升级](docs/operations.md#数据库安装与升级)。

应用入口使用 HTTPS，可由 IAM 或受信代理终止 TLS。默认不信任转发头；HTTP 回源须显式启用受信代理模式，并限制 IAM 端口仅由代理访问。切换到仅含 `iam_runtime` 凭据的运行环境，以 `runtime` profile 关闭启动迁移并在监听前核查数据库身份；误用所有者账号或出现受保护表权限扩大时拒绝启动：

```bash
java -jar target/iam.jar --spring.profiles.active=runtime
```

## 应用接入

应用没有默认账号或公开注册入口。用户需经授权创建，由组织核验身份并交付一次性开通凭据，完成密码设置后登录。

身份前端通过同源 HTTPS 调用 IAM，使用会话 Cookie 和 CSRF 防护；前后端可独立部署，但浏览器访问需使用同一固定 origin。代理可使用经过验证的 HTTPS 回源，或在受保护内网使用显式受信的 HTTP 回源；不开放跨源凭据访问。

IAM 会话与应用会话分别管理，IAM 会话不能作为业务 API 的访问令牌。接口字段、请求示例、响应及错误由 OpenAPI 描述；跨请求流程见 [接入指南](docs/integration.md)。

## 接口文档工具

接口规范由 springdoc 根据控制器和 DTO 生成，并补充 Spring Security 过滤器处理的登录、退出和协议端点。默认关闭文档入口；需要导出时，在完成数据库和 HTTPS 配置后启用 `documentation` profile：

```bash
java -jar target/iam.jar --spring.profiles.active=runtime,documentation
```

使用有效会话读取 `/v3/api-docs`（JSON）或 `/v3/api-docs.yaml`（YAML），导出规范到本地后，通过 [独立预览工具](tools/swagger/README.md)校验和查看。

## 运行维护

主 HTTPS 端口提供无需登录的 `GET /livez` 和 `GET /readyz`，仅返回总体状态。前者检查进程，后者检查数据库、必要审计、授权保护配置与签发材料；不可用返回 503。故障定位、管理员恢复及密钥维护见 [运维指南](docs/operations.md)。

## 反馈与维护

使用问题和改进建议可在 [GitHub Issues](https://github.com/iXayda/IAM/issues) 提出。项目由 ka1i 维护，联系邮箱：<iXayda@outlook.com>。

漏洞请按 [安全策略](SECURITY.md)私下报告；参与开发前请阅读 [贡献指南](CONTRIBUTING.md)。

## 许可证

除另有声明的文件外，本项目采用 [Apache License 2.0](LICENSE)。[社区行为准则](CODE_OF_CONDUCT.md)按其声明采用 CC BY-SA 4.0。
