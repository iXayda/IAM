# 许可归集维护

生成发行用依赖清单和许可全文：

```bash
./mvnw -Plicenses generate-resources
```

`license-maven-plugin` 在 `target/third-party/` 生成 `THIRD-PARTY-NOTICES` 和 `licenses/`。只包含运行相关依赖，排除测试库及未装入可执行 JAR 的 starter；普通构建不启用此 profile。

打包时 `collect-notices.sh` 核对实际 JAR 与 Maven 清单，保留上游版权、NOTICE、原始 POM，并补入 Spring Boot 注入的工具组件。`INVENTORY.tsv` 记录实际 JAR 的坐标和 SHA-256。原生制品另附构建所用 Oracle GraalVM 的声明。

新增或升级依赖时复核生成结果。`license-overrides.xml` 使用[插件标准格式](https://www.mojohaus.org/license-maven-plugin/download-licenses-mojo.html#licensesConfigFile)补齐缺失地址及记录分发选择；配置和本 README 只用于构建维护，不复制到二进制包或镜像。

- Spring Session 4.1.1 的 POM 标注 Broadcom Foundation License，JAR 及[对应源码](https://github.com/spring-projects/spring-session/blob/4.1.1/LICENSE.txt)附 Apache 2.0。保留两份原件并在来源信息中注明差异；配置中的 `approved` 仅允许该无 URL 条目跳过下载，不改写许可名称。
