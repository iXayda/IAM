# 贡献指南

问题和建议通过 [GitHub Issues](https://github.com/iXayda/IAM/issues)提出；疑似安全漏洞按 [安全策略](SECURITY.md)私下报告。涉及认证、授权、恢复流程或部署边界的大范围调整，先讨论方案。参与项目交流和贡献时，请遵守 [社区行为准则](CODE_OF_CONDUCT.md)。

测试使用隔离数据、测试 issuer 和临时生成的秘密，不依赖生产凭据。不要提交本地日志、验收结果、截图、trace、数据库归档，或含真实配置及凭据的本地环境文件；脱敏配置模板可随功能维护。

## 保持改动完整

- 每次提交聚焦一个可审阅的行为，实施、对应测试和必要说明一起交付。
- README 保持简洁、稳定的使用入口；用户可见变更整理到 [CHANGELOG.md](CHANGELOG.md)。

提交标题使用简短的 Conventional Commits 格式，例如 `feat(sessions): revoke account sessions`。scope 根据实际变更选择，不改写与本次贡献无关的历史。

## AI / LLM 辅助贡献

允许使用 AI / LLM 辅助编写代码、测试和文档。贡献者须在提交评审前阅读、理解并审查全部内容，执行相关检查，对贡献负责，并能回答评审问题。模型输出不能代替真实验证，不得编造测试结果或引用依据。

- 实质使用 AI 生成内容时，在 PR 描述中简要说明工具、使用范围和实际验证情况，无需提交提示词或对话记录。
- Git 署名使用实际贡献者身份，不将工具设为作者或共同作者；工具使用情况通过 PR 描述说明。
- 核对工具条款及已识别第三方材料的来源和许可证，确认与项目交付兼容，保留必要声明。AI 生成或改写不会消除原有版权。
- 使用脱敏或合成数据，不向未经授权的外部 AI 服务发送真实凭据、私钥、数据库归档、人员资料或未公开漏洞信息。
- AI 代理对外发布贡献、评论或评审意见前，须经过人工审查确认；AI 评审不能代替人工审核。

参考：[LLVM AI Tool Use Policy](https://llvm.org/docs/AIToolPolicy.html)、[ASF Generative Tooling Guidance](https://www.apache.org/legal/generative-tooling.html)。

## 提交 Pull Request

说明具体问题、变更后的行为、相关验证和剩余限制，示例及证据不得包含秘密。

贡献应遵循目标文件的许可声明；社区行为准则采用其中声明的 CC BY-SA 4.0。此处未另行定义贡献者协议。
