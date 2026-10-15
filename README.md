# IAM

简体中文 | [English](README.en.md)

IAM 是面向单个组织、多个自有应用的身份与访问管理项目，让各应用共用账号和登录体系，集中管理用户、应用角色、会话和安全审计。

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

启动应用前配置专用 PostgreSQL 数据库连接：

| 环境变量 | 内容 |
| --- | --- |
| `SPRING_DATASOURCE_URL` | PostgreSQL JDBC 连接地址 |
| `SPRING_DATASOURCE_USERNAME` | 数据库用户名 |
| `SPRING_DATASOURCE_PASSWORD` | 数据库密码，由运行环境注入 |

数据库账号需要具备建表和执行迁移的权限。Flyway 在启动时创建或升级表结构。

配置就绪后启动：

```bash
java -jar target/iam.jar
```

## 反馈与维护

使用问题和改进建议可在 [GitHub Issues](https://github.com/iXayda/IAM/issues) 提出。项目由 ka1i 维护，联系邮箱：<iXayda@outlook.com>。

漏洞请按 [安全策略](SECURITY.md)私下报告；参与开发前请阅读 [贡献指南](CONTRIBUTING.md)。

## 许可证

除另有声明的文件外，本项目采用 [Apache License 2.0](LICENSE)。[社区行为准则](CODE_OF_CONDUCT.md)按其声明采用 CC BY-SA 4.0。
