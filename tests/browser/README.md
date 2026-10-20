# 浏览器与独立应用验证

使用真实 Chromium、Docker PostgreSQL 18、受限数据库运行身份和 HTTPS。每次运行创建独立数据库、管理员和临时密钥，整套验证共用该夹具，应用验证启动实际 `examples/oidc` 中的 BFF 与资源进程。

## 准备环境

需要 JDK 21、Node.js 22、可用的 Docker，以及 Chromium 运行库。

在仓库根目录准备 Java 夹具及测试类路径：

```bash
./mvnw test-compile dependency:build-classpath -Dmdep.includeScope=test -Dmdep.outputFile=target/acceptance-classpath.txt
npm --prefix examples/oidc ci --ignore-scripts
npm --prefix tests/browser ci --ignore-scripts
```

在 `tests/browser` 安装锁定版本对应的 Chromium，然后回到仓库根目录：

```bash
cd tests/browser
npx --no-install playwright install chromium --only-shell
cd ../..
```

以下运行命令均在仓库根目录执行。

## 运行验证

执行整套 JVM 浏览器与独立应用验证：

```bash
node tests/browser/verify.mjs
```

验证会等待真实 TOTP 步长，每个管理敏感操作使用新的动态码，完整运行需要数分钟。不得通过放宽 MFA、重设数据库计数器或跳过场景缩短等待。

## 受信代理验证

验证外部 HTTPS 入口通过受信 HTTP 回源连接 IAM：

```bash
node tests/browser/verify.mjs --proxy
```

`--proxy` 启用受信代理验证；测试入口清除外来转发头，再设置 HTTPS 和真实来源地址。未指定时继续使用经过证书验证的 HTTPS 回源。

## 结果与故障定位

脚本依据浏览器子进程的退出码判断结果。成功路径输出 `browser_verification_passed` 和检查数；失败路径输出阶段标签及可用的 HTTP 状态。按最后输出的阶段定位后，重新执行整套验证。

失败时不输出 Playwright 异常、协议 URL、响应体或截图，不记录浏览器 trace。凭据与进程日志位于权限受限的临时目录，结束时清理，数据库容器随夹具结束而销毁。可以将脱敏阶段输出保存到 `target/`，不要提交本地验收结果。

## 覆盖与边界

测试为每次运行生成只包含回环地址的短期 TLS 证书。Node 使用该证书建立信任并保留主机名验证；Chromium 仅对本次证书的 SPKI 精确授权，不全局忽略 HTTPS 错误。各 origin、端口、密码和保护密钥均隔离生成，不需要真实生产配置。

浏览器负责 Cookie、CSRF 和各场景的身份前端请求；脚本不复制 Cookie 或以 SQL 改写业务状态来代替交互。覆盖开通及证明重放、本人资料、管理 MFA / 普通角色隔离、秘密单次展示与清理、两个独立应用的一次密码登录及 SSO、UserInfo、回调重放、刷新、跨资源拒绝、局部与 IAM 退出、授权 / 全部下线、密码恢复、因素注册 / 更换 / 恢复、管理员强制下线及审计秘密检查。

Java `./mvnw clean verify` 和示例 `npm test` 继续分别验证事务、协议失败、并发、异常输入和故障回滚；浏览器检查不替代这些测试。生产容量、实际人员及交付渠道、业务应用和域名配置仍须使用组织确认的输入验收。
