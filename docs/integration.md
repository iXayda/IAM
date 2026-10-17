# 接入指南

本指南面向独立身份前端的接入者，说明跨请求的流程及约束。接口字段、请求编码、响应和错误以对应构建的 OpenAPI 为准。

## 接入前提

身份前端负责 IAM 登录与账号交互，由接入方提供。它与 IAM 接口使用同一固定 HTTPS origin；入口代理可使用经过证书链及主机名验证的 HTTPS 回源，或在受保护内网使用显式受信的 HTTP 回源。入口清除并重设外来转发头，不开放跨源凭据访问。

## HTTPS 与受信代理

默认由 IAM 提供 HTTPS，忽略转发头。由 Nginx、网关或 WAF 终止 TLS 时，可继续使用经过验证的 HTTPS 回源，也可在受保护内网使用 HTTP 回源。HTTP 回源设置：

```bash
export SERVER_SSL_ENABLED=false
export SERVER_FORWARD_HEADERS_STRATEGY=NATIVE
export SERVER_TOMCAT_REMOTEIP_INTERNAL_PROXIES='127\.0\.0\.1'
```

`internal-proxies` 是匹配实际代理来源 IP 的正则；上例仅适用于代理与 IAM 通过同一主机的回环地址通信。跨主机或容器部署须替换为 IAM 实际看到的代理地址，限定网络访问，并在入口清除、重设转发头。不能留空、使用通配全部来源的表达式，或信任客户端自报的代理链。

Nginx 的最小 HTTP 回源示例，域名和证书路径按部署环境替换；身份前端的静态资源路由由接入方配置：

```nginx
server {
    listen 443 ssl;
    server_name iam.example.com;
    ssl_certificate /etc/nginx/tls/iam.crt;
    ssl_certificate_key /etc/nginx/tls/iam.key;

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host iam.example.com;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header Forwarded "";
        proxy_set_header X-Forwarded-Host "";
        proxy_set_header X-Forwarded-Port "";
        proxy_set_header X-Forwarded-Prefix "";
        proxy_set_header X-Forwarded-Ssl "";
    }
}
```

IAM 仅还原受信连接的 HTTPS 状态和来源 IP，不使用转发 Host 或端口选择应用地址。多级代理须逐跳配置来源信任，避免把客户端输入当作真实地址；来源地址影响尝试预算和审计。浏览器仍使用同源 HTTPS，Cookie 的 Secure、HttpOnly 与 CSRF 要求保持不变。

## 身份前端

### 登录与退出

浏览器使用 `credentials: 'same-origin'` 调用接口：

1. 从 `GET /api/csrf` 取得本会话的 CSRF 值及请求头名。
2. 以 JSON 调用 `POST /login`，由 JavaScript 处理 HTTP 状态和响应。
3. 登录成功后重新获取 CSRF；通过 `GET /api/me` 查询当前用户。
4. 使用当前 CSRF 调用 `POST /logout`，结束当前 IAM 会话。

Cookie `__Host-IAMSESSION` 使用 Secure、HttpOnly、Path=/ 和 SameSite=Lax。不要读取、复制 Cookie，或将 IAM 会话当作业务 API 的 Bearer Token。写操作使用 POST，不能由 GET 触发；其他接口按规范选择 JSON 或表单编码。

入口不得记录请求体、Cookie、Authorization 或秘密响应。页面配置适当的 CSP、禁止嵌入和 `no-referrer`，避免第三方脚本接触凭据；敏感输入在发送后清空，不进入 URL、日志、埋点、错误上报或浏览器持久存储。

## 退出与撤销

| 操作 | 作用范围 |
| --- | --- |
| IAM 退出 | 结束当前 IAM 浏览器会话 |
