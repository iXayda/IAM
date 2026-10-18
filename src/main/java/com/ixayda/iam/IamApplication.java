package com.ixayda.iam;

import com.ixayda.iam.cli.AdministratorBootstrapCommand;

import io.swagger.v3.oas.annotations.OpenAPIDefinition;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeIn;
import io.swagger.v3.oas.annotations.enums.SecuritySchemeType;
import io.swagger.v3.oas.annotations.info.Info;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.security.SecurityScheme;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
@OpenAPIDefinition(info = @Info(title = "IAM API", version = "0.1.0",
		description = "IAM 身份会话 API，供受信任的独立身份前端或身份服务端客户端使用。"
				+ "先获取 CSRF 令牌并保留会话 Cookie，再携带令牌提交 JSON 登录；成功后接受轮换 Cookie，重新获取令牌并查询本人资料。"
				+ "浏览器调用要求同源 HTTPS；服务不提供登录页面，也未开放跨源凭据访问。"
				+ "当前未提供 OIDC 或业务 API Access Token；业务应用的 OIDC 授权码与 PKCE 接入随协议实现交付。"),
		security = @SecurityRequirement(name = "browserSession"))
@SecurityScheme(name = "browserSession", type = SecuritySchemeType.APIKEY, in = SecuritySchemeIn.COOKIE,
		paramName = "__Host-IAMSESSION", description = "浏览器会话 Cookie；通过 /api/csrf 创建匿名会话，登录成功后轮换为已认证会话，由浏览器自动携带。")
public class IamApplication {

	public static void main(String[] args) {
		if (args.length > 0 && args[0].equals("bootstrap-admin")) {
			AdministratorBootstrapCommand.run(IamApplication.class, args);
			return;
		}
		SpringApplication.run(IamApplication.class, args);
	}

}
