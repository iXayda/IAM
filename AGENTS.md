# AGENTS.md

适用于整个仓库。通用贡献及 AI 使用要求见 [贡献指南](CONTRIBUTING.md)；漏洞报告按 [安全策略](SECURITY.md)处理。

## 仓库导航

- `src/main/java/com/ixayda/iam/`：Java 源码；`src/test/java/com/ixayda/iam/`：Java 测试及共享夹具。

## 开发环境

- 在仓库根目录使用 Maven Wrapper 和 Oracle JDK 21；Java 集成测试需要 Docker。

执行完整 Java 验证并构建 JAR：

```bash
./mvnw clean verify
```

按 [运行说明](README.md#开发与运行)配置数据库及 HTTPS 后启动 Web 服务：

```bash
java -jar target/iam.jar
```

## 代码约定

- 修改前阅读受影响实现及已有测试，沿用该文件的缩进、导入和命名方式。
- 控制器、安全适配器及 CLI 调用 `service`，持久化访问放在 `repository`；`model` 不依赖 Spring 或数据库 API。遵循 [ArchitectureTests](src/test/java/com/ixayda/iam/ArchitectureTests.java)中的依赖和循环约束；任务涉及架构调整时同步更新实现、约束测试及相关说明。
- 数据结构变化新增 `src/main/resources/db/migration/` 下的 Flyway 迁移，不改写已交付迁移。
- HTTP 契约变化同步更新受影响控制器、DTO、OpenAPI 和测试。由 Spring Security 处理的登录及退出端点，另核对 [IdentityBrowserOpenApiConfiguration](src/main/java/com/ixayda/iam/security/IdentityBrowserOpenApiConfiguration.java)中的描述。

## 测试与检查

先运行受影响测试；行为变化同步更新相应测试，按涉及的风险覆盖拒绝、重放、并发和故障回滚。修正后重新测试并审阅 diff。

单个 Java 测试示例，替换为受影响的测试类：

```bash
./mvnw -Dtest=PasswordPolicyTests test
```

包结构或依赖变化时执行：

```bash
./mvnw -Dtest=ArchitectureTests test
```

| 改动 | 补充检查 |
| --- | --- |
| 仅文档 | 检查链接、示例及说明与实现的一致性；涉及可执行示例时验证受影响命令 |

## 安全注意点

- 安全状态变更与必要成功审计保持事务原子性。
- 不通过放宽 HTTPS issuer、认证、授权、CSRF、MFA、重放或尝试预算校验，或跳过断言使测试通过。
- 验证使用隔离数据库、合成数据和临时凭据，不使用生产秘密，不提交日志、数据库归档或本地环境文件。

## 提交与 PR

- 提交标题使用简短的 Conventional Commits 格式，例如 `feat(sessions): revoke account sessions`；scope 根据实际变更选择。
- 提交前审阅 diff，检查改动范围、路径、文件及方法命名、分层和安全边界，确认相关检查通过。
- PR 说明问题、修改后的行为、实际验证及剩余限制；区分本地结果和 CI 结果，未运行的检查明确说明原因。
- 保留与任务无关的工作区改动和历史。
