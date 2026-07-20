package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.time.Instant;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.ixayda.iam.auth.MfaChallenge;
import com.ixayda.iam.auth.MfaFactor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.security.web.savedrequest.SavedRequest;
import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.util.HtmlUtils;

@Controller
class AuthorizationMfaLoginPageController {

	static final String PATH = "/login/mfa";

	static final String CHALLENGE_ATTRIBUTE =
			AuthorizationMfaLoginPageController.class.getName() + ".CHALLENGE";

	@GetMapping(value = PATH, produces = MediaType.TEXT_HTML_VALUE)
	@ResponseBody
	ResponseEntity<String> login(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session == null || !(session.getAttribute(CHALLENGE_ATTRIBUTE) instanceof MfaChallenge challenge)) {
			return redirect("/login");
		}
		if (!(session.getAttribute(AuthorizationLoginDetailsSource.SAVED_REQUEST_ATTRIBUTE) instanceof SavedRequest saved)
				|| !"GET".equals(saved.getMethod())
				|| !AllowlistedAuthorizationRequestConverter.hasValidParameters(saved.getParameterMap())
				|| !Instant.now().isBefore(challenge.expiresAt())) {
			session.removeAttribute(CHALLENGE_ATTRIBUTE);
			return redirect("/login?error");
		}
		Object csrfAttribute = request.getAttribute(CsrfToken.class.getName());
		if (!(csrfAttribute instanceof CsrfToken csrf)) {
			session.removeAttribute(CHALLENGE_ATTRIBUTE);
			return redirect("/login?error");
		}
		return ResponseEntity.ok()
			.contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
			.header(HttpHeaders.CACHE_CONTROL, "no-store")
			.header("Content-Security-Policy",
					"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
			.header("Referrer-Policy", "no-referrer")
			.body(render(challenge, csrf));
	}

	private static ResponseEntity<String> redirect(String location) {
		return ResponseEntity.status(HttpStatus.FOUND).location(URI.create(location)).build();
	}

	private static String render(MfaChallenge challenge, CsrfToken csrf) {
		String factorControl;
		if (challenge.factors().size() == 1) {
			MfaFactor factor = challenge.factors().iterator().next();
			factorControl = "<input type=\"hidden\" name=\"factor\" value=\"" + factorValue(factor) + "\">"
					+ "<p class=\"method\">" + factorLabel(factor) + "</p>";
		}
		else {
			StringBuilder options = new StringBuilder();
			if (challenge.supports(MfaFactor.TOTP)) {
				options.append("<option value=\"totp\">Authenticator code</option>");
			}
			if (challenge.supports(MfaFactor.RECOVERY_CODE)) {
				options.append("<option value=\"recovery_code\">Recovery code</option>");
			}
			factorControl = "<label for=\"factor\">Verification method</label><select id=\"factor\" name=\"factor\">"
					+ options + "</select>";
		}
		return """
				<!doctype html>
				<html lang="en">
				<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width,initial-scale=1">
				<title>Verify your identity</title>
				<style>
				:root{color-scheme:light dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:#17202a}main{min-height:100vh;display:grid;place-items:center;padding:24px}.panel{width:min(100%%,440px);background:#fff;border:1px solid #d8dee4;border-radius:8px;box-shadow:0 12px 32px rgba(23,32,42,.10);overflow:hidden}.heading{padding:28px 30px 22px;border-bottom:1px solid #e5e9ed}.eyebrow{margin:0 0 8px;color:#52606d;font-size:13px;font-weight:700;text-transform:uppercase}.heading h1{margin:0;font-size:25px;line-height:1.25}.heading p{margin:12px 0 0;color:#52606d;line-height:1.5}.content{padding:24px 30px 30px}label{display:block;margin:18px 0 8px;font-size:14px;font-weight:700}.method{margin:0 0 18px;color:#52606d}input[type=text],select{width:100%%;min-height:44px;border:1px solid #aab4be;border-radius:6px;background:#fff;color:#17202a;padding:9px 11px;font:inherit;letter-spacing:0}input[type=text]:focus,select:focus{outline:3px solid rgba(23,107,87,.22);border-color:#176b57}button{width:100%%;min-height:44px;margin-top:22px;border:1px solid #176b57;border-radius:6px;background:#176b57;color:#fff;font:inherit;font-weight:700;cursor:pointer}@media(max-width:520px){main{padding:0}.panel{min-height:100vh;border:0;border-radius:0;box-shadow:none}.heading,.content{padding-left:22px;padding-right:22px}}@media(prefers-color-scheme:dark){body{background:#11161b;color:#e8edf2}.panel{background:#1b2229;border-color:#35404a}.heading{border-color:#35404a}.heading p,.eyebrow,.method{color:#acb8c3}input[type=text],select{background:#11161b;color:#e8edf2;border-color:#64717d}}
				</style>
				</head>
				<body><main><article class="panel" aria-labelledby="title">
				<header class="heading"><p class="eyebrow">Security check</p><h1 id="title">Verify your identity</h1><p>Complete the second authentication step to continue.</p></header>
				<form class="content" method="post" action="%s">
				%s
				<label for="code">Verification code</label>
				<input id="code" name="code" type="text" inputmode="text" autocomplete="one-time-code" maxlength="23" required autofocus>
				<input type="hidden" name="%s" value="%s">
				<button type="submit">Continue</button>
				</form></article></main></body>
				</html>
				""".formatted(PATH, factorControl, HtmlUtils.htmlEscape(csrf.getParameterName()),
				HtmlUtils.htmlEscape(csrf.getToken()));
	}

	private static String factorValue(MfaFactor factor) {
		return factor == MfaFactor.TOTP ? "totp" : "recovery_code";
	}

	private static String factorLabel(MfaFactor factor) {
		return factor == MfaFactor.TOTP ? "Authenticator code" : "Recovery code";
	}

}
