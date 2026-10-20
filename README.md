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

数据库账号需要具备建表和执行迁移的权限。Flyway 在启动时创建或升级表结构。TOTP 保护密钥需要持久保存并限制读取权限，不应提交到仓库或在每次启动时重新生成。

应用入口使用 HTTPS，可由 IAM 或受信代理终止 TLS。默认不信任转发头；HTTP 回源须显式启用受信代理模式，并限制 IAM 端口仅由代理访问。配置就绪后启动：

```bash
java -jar target/iam.jar
```

## 应用接入

应用没有默认账号或公开注册入口。用户需经授权创建，由组织核验身份并交付一次性开通凭据，完成密码设置后登录。

身份前端通过同源 HTTPS 调用 IAM，使用会话 Cookie 和 CSRF 防护；前后端可独立部署，但浏览器访问需使用同一固定 origin。代理可使用经过验证的 HTTPS 回源，或在受保护内网使用显式受信的 HTTP 回源；不开放跨源凭据访问。

IAM 会话与应用会话分别管理，IAM 会话不能作为业务 API 的访问令牌。接口字段、请求示例、响应及错误由 OpenAPI 描述；跨请求流程见 [接入指南](docs/integration.md)。

## 接口文档工具

接口规范由 springdoc 根据控制器和 DTO 生成，并补充 Spring Security 过滤器处理的登录、退出和协议端点。默认关闭文档入口；需要导出时，在完成数据库和 HTTPS 配置后启用 `documentation` profile：

```bash
java -jar target/iam.jar --spring.profiles.active=documentation
```

使用有效会话读取 `/v3/api-docs`（JSON）或 `/v3/api-docs.yaml`（YAML），导出规范到本地后，通过 [独立预览工具](tools/swagger/README.md)校验和查看。

## 运行维护

管理员初始化、恢复及部署维护说明见 [运维指南](docs/operations.md)。

## 反馈与维护

使用问题和改进建议可在 [GitHub Issues](https://github.com/iXayda/IAM/issues) 提出。项目由 ka1i 维护，联系邮箱：<iXayda@outlook.com>。

漏洞请按 [安全策略](SECURITY.md)私下报告；参与开发前请阅读 [贡献指南](CONTRIBUTING.md)。

## 许可证

除另有声明的文件外，本项目采用 [Apache License 2.0](LICENSE)。[社区行为准则](CODE_OF_CONDUCT.md)按其声明采用 CC BY-SA 4.0。
