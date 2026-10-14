# AGENTS.md

适用于整个仓库。通用贡献及 AI 使用要求见 [贡献指南](CONTRIBUTING.md)；漏洞报告按 [安全策略](SECURITY.md)处理。

## 仓库导航

- `src/main/java/com/ixayda/iam/`：Java 源码；`src/test/java/com/ixayda/iam/`：Java 测试及共享夹具。

## 开发环境

- 在仓库根目录使用 Maven Wrapper 和 Oracle JDK 21。

执行完整 Java 验证并构建 JAR：

```bash
./mvnw clean verify
```

## 代码约定

- 修改前阅读受影响实现及已有测试，沿用该文件的缩进、导入和命名方式。

## 测试与检查

先运行受影响测试；行为变化同步更新相应测试，按涉及的风险覆盖拒绝、重放、并发和故障回滚。修正后重新测试并审阅 diff。

单个 Java 测试示例，替换为受影响的测试类：

```bash
./mvnw -Dtest=PasswordPolicyTests test
```

| 改动 | 补充检查 |
| --- | --- |
| 仅文档 | 检查链接、示例及说明与实现的一致性；涉及可执行示例时验证受影响命令 |

## 安全注意点

- 验证使用隔离数据库、合成数据和临时凭据，不使用生产秘密，不提交日志、数据库归档或本地环境文件。

## 提交与 PR

- 提交标题使用简短的 Conventional Commits 格式，例如 `feat(sessions): revoke account sessions`；scope 根据实际变更选择。
- 提交前审阅 diff，检查改动范围、路径、文件及方法命名、分层和安全边界，确认相关检查通过。
- PR 说明问题、修改后的行为、实际验证及剩余限制；区分本地结果和 CI 结果，未运行的检查明确说明原因。
- 保留与任务无关的工作区改动和历史。
