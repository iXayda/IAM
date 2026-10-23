# 贡献指南

问题和建议通过 [GitHub Issues](https://github.com/iXayda/IAM/issues)提出；疑似安全漏洞按 [安全策略](SECURITY.md)私下报告。涉及认证、授权、恢复流程或部署边界的大范围调整，先讨论方案。参与项目交流和贡献时，请遵守 [社区行为准则](CODE_OF_CONDUCT.md)。

## 开发准备

使用 Oracle JDK 21、仓库中的 Maven Wrapper 及可用的 Docker。Java 集成测试启动隔离的 PostgreSQL 18 容器；应用示例和浏览器验证需要 Node.js 22。

执行 Java 验证：

```bash
./mvnw clean verify
```

修改应用示例时执行：

```bash
npm --prefix examples/oidc ci --ignore-scripts
npm --prefix examples/oidc test
npm --prefix examples/oidc run check
```

浏览器依赖和场景命令见 [浏览器验证说明](tests/browser/README.md)。原生运行相关改动还需完成 GraalVM 构建，并对原生程序执行对应场景；构建入口见 [README](README.md)。

测试使用隔离数据、测试 issuer 和临时生成的秘密，不依赖生产凭据。不要提交本地日志、验收结果、截图、trace、数据库归档，或含真实配置及凭据的本地环境文件；脱敏配置模板可随功能维护。

## 保持改动完整

- 每次提交聚焦一个可审阅的行为，实施、对应测试和必要说明一起交付。
- API 契约变化时，同步更新受影响的控制器、DTO、OpenAPI 和测试；Spring Security 提供的端点也需维护其独立描述，并核对请求编码、CSRF、错误和权限语义。
- 数据结构修改新增 Flyway 迁移，不改写已交付迁移；表和数据库访问变化时检查显式运行授权清单。
- 业务变更与必要成功审计保持事务原子性，按受影响的行为和风险选择拒绝、重放、并发及故障回滚检查。
- 沿用现有分层和命名：控制器及安全适配器调用服务，仓储负责持久化，模型不依赖 Spring 或数据库 API。[ArchitectureTests](src/test/java/com/ixayda/iam/ArchitectureTests.java)约束允许的依赖及循环。
- README 保持简洁、稳定的使用入口；详细操作和设计写入 [文档](docs/README.md)，用户可见变更整理到 [CHANGELOG.md](CHANGELOG.md)。

提交标题使用简短的 Conventional Commits 格式，例如 `feat(sessions): revoke account sessions`。scope 根据实际变更选择，不改写与本次贡献无关的历史。

## AI / LLM 辅助贡献

允许使用 AI / LLM 辅助编写代码、测试和文档。贡献者须在提交评审前阅读、理解并审查全部内容，执行相关检查，对贡献负责，并能回答评审问题。模型输出不能代替真实验证，不得编造测试结果或引用依据。

- 实质使用 AI 生成内容时，在 PR 描述中简要说明工具、使用范围和实际验证情况，无需提交提示词或对话记录。
- Git 署名使用实际贡献者身份，不将工具设为作者或共同作者；工具使用情况通过 PR 描述说明。
- 核对工具条款及已识别第三方材料的来源和许可证，确认与项目交付兼容，保留必要声明。AI 生成或改写不会消除原有版权。
- 使用脱敏或合成数据，不向未经授权的外部 AI 服务发送真实凭据、私钥、数据库归档、人员资料或未公开漏洞信息。
- AI 代理对外发布贡献、评论或评审意见前，须经过人工审查确认；AI 评审不能代替人工审核。

参考：[LLVM AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html)、[ASF Generative Tooling Guidance](https://www.apache.org/legal/generative-tooling.html)。

## 弱密码清单维护

项目自行维护 [password-blocklist.txt](src/main/resources/credential/password-blocklist.txt)，配合最小长度及账号、服务名检查使用，不代表完整的泄露密码数据库。

条目使用 UTF-8，一行一个完整密码。规范化后须满足解析器的 15–256 个 Unicode 码点范围，更短的密码已由策略拒绝。比较采用 NFC 和与语言环境无关的小写处理；忽略空行及以 `#` 开头的行。避免规范化后的重复条目，不擅自裁剪或改写预期密码。

补充条目时说明依据并更新相关策略检查。不得加入真实用户密码、个人资料或下载的泄露数据；引入外部清单前需确认许可证和来源。

## 提交 Pull Request

说明具体问题、变更后的行为、相关验证和剩余限制，示例及证据不得包含秘密。按影响检查现有工作流中的 Java、应用示例、浏览器、原生及容器任务，合并前确保 CI 通过。

贡献应遵循目标文件的许可声明：项目代码采用 [Apache License 2.0](LICENSE)，社区行为准则采用其中声明的 CC BY-SA 4.0。此处未另行定义贡献者协议。

## 候选版本发布

将 POM 版本设为 `x.y.z-rc.N` 并更新变更日志后，在 GitHub Actions 手动运行 [Build and Release](.github/workflows/release.yml)。工作流验证所选提交，并行构建 JVM 和 Native 镜像；全部通过后，在本次构建的提交上创建 `v<版本>` 注释标签和 GitHub 预发布版，上传 JAR、Linux amd64 原生包、镜像归档、源码、许可声明和校验和。新增或升级依赖时核对其许可元数据和原始声明，按[许可归集说明](.github/packaging/README.md)检查生成结果及必要补正。

附件完整且校验一致后才公开预发布版；上传中断可重试失败的发布任务，已有标签和已完成附件不会被覆盖。同次运行草稿中未完成的空附件占位会清理后重传。下载后按 `SHA256SUMS` 校验，部署前仍需验收目标环境配置。
