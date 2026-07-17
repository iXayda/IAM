package com.ixayda.iam.authorization.internal;

import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

import jakarta.servlet.http.HttpServletRequest;

import com.ixayda.iam.authorization.AuthorizationUserAuthentication;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsent;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2TokenType;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.stereotype.Controller;
import org.springframework.transaction.annotation.Isolation;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.ResponseBody;
import org.springframework.web.server.ResponseStatusException;
import org.springframework.web.util.HtmlUtils;
import org.springframework.web.util.UriComponentsBuilder;
import org.springframework.web.util.UriUtils;

@Controller
class AuthorizationConsentController {

	static final String CONSENT_PATH = "/oauth2/consent";

	static final String DENIAL_PATH = CONSENT_PATH + "/deny";

	private static final OAuth2TokenType STATE_TOKEN_TYPE = new OAuth2TokenType(OAuth2ParameterNames.STATE);

	private static final int MAXIMUM_STATE_LENGTH = 2_048;

	private static final int MAXIMUM_SCOPE_PARAMETER_LENGTH = 4_096;

	private final RegisteredClientRepository clients;

	private final JdbcOAuth2AuthorizationService authorizations;

	private final OAuth2AuthorizationConsentService consents;

	private final String authorizationEndpoint;

	AuthorizationConsentController(RegisteredClientRepository clients, JdbcOAuth2AuthorizationService authorizations,
			OAuth2AuthorizationConsentService consents, AuthorizationServerSettings settings) {
		this.clients = clients;
		this.authorizations = authorizations;
		this.consents = consents;
		this.authorizationEndpoint = settings.getAuthorizationEndpoint();
	}

	@GetMapping(value = CONSENT_PATH, produces = MediaType.TEXT_HTML_VALUE)
	@ResponseBody
	ResponseEntity<String> consent(HttpServletRequest servletRequest, Authentication authentication,
			@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
			@RequestParam(OAuth2ParameterNames.SCOPE) String scope,
			@RequestParam(OAuth2ParameterNames.STATE) String state) {
		Object csrfAttribute = servletRequest.getAttribute(CsrfToken.class.getName());
		if (!(csrfAttribute instanceof CsrfToken csrf)) {
			throw invalidRequest();
		}
		ConsentView view = view(authentication, clientId, scope, state, csrf);
		return ResponseEntity.ok()
			.contentType(MediaType.parseMediaType("text/html;charset=UTF-8"))
			.header(HttpHeaders.CACHE_CONTROL, "no-store")
			.header("Content-Security-Policy",
					"default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
			.header("Referrer-Policy", "no-referrer")
			.body(render(view));
	}

	@PostMapping(DENIAL_PATH)
	@Transactional(isolation = Isolation.READ_COMMITTED)
	ResponseEntity<Void> deny(Authentication authentication,
			@RequestParam(OAuth2ParameterNames.CLIENT_ID) String clientId,
			@RequestParam(OAuth2ParameterNames.STATE) String state) {
		ConsentRequest consentRequest = resolve(authentication, clientId, state);
		OAuth2AuthorizationRequest request = consentRequest.request();
		String redirectUri = request.getRedirectUri();
		if (redirectUri == null || !consentRequest.client().getRedirectUris().contains(redirectUri)) {
			throw invalidRequest();
		}
		if (!this.authorizations.removeIfCurrent(consentRequest.authorization())) {
			throw new ResponseStatusException(HttpStatus.CONFLICT, "Authorization consent request is no longer pending");
		}
		return ResponseEntity.status(HttpStatus.FOUND)
			.location(denialRedirect(redirectUri, request.getState()))
			.build();
	}

	static URI denialRedirect(String redirectUri, String state) {
		UriComponentsBuilder redirect = UriComponentsBuilder.fromUriString(redirectUri)
			.queryParam(OAuth2ParameterNames.ERROR, OAuth2ErrorCodes.ACCESS_DENIED);
		if (state != null) {
			redirect.queryParam(OAuth2ParameterNames.STATE, UriUtils.encode(state, StandardCharsets.UTF_8));
		}
		return URI.create(redirect.build(true).toUriString());
	}

	private ConsentView view(Authentication authentication, String clientId, String scope, String state,
			CsrfToken csrf) {
		ConsentRequest consentRequest = resolve(authentication, clientId, state);
		Set<String> queryScopes = parseScopes(scope);
		OAuth2AuthorizationRequest request = consentRequest.request();
		if (!queryScopes.equals(request.getScopes())) {
			throw invalidRequest();
		}
		RegisteredClient client = consentRequest.client();
		OAuth2AuthorizationConsent current = this.consents.findById(client.getId(), authentication.getName());
		Set<String> authorizedScopes = current == null ? Set.of() : current.getScopes();
		return new ConsentView(client.getClientName(), clientId, authentication.getName(), state, request.getScopes(),
				authorizedScopes, this.authorizationEndpoint, DENIAL_PATH, csrf.getParameterName(), csrf.getToken());
	}

	private ConsentRequest resolve(Authentication authentication, String clientId, String state) {
		if (!(authentication instanceof AuthorizationUserAuthentication) || !authentication.isAuthenticated()
				|| state == null || state.isEmpty() || state.length() > MAXIMUM_STATE_LENGTH) {
			throw invalidRequest();
		}
		OAuth2Authorization authorization;
		try {
			authorization = this.authorizations.findByToken(state, STATE_TOKEN_TYPE);
		}
		catch (IllegalArgumentException exception) {
			throw invalidRequest();
		}
		if (authorization == null || !authentication.getName().equals(authorization.getPrincipalName())) {
			throw invalidRequest();
		}
		RegisteredClient client = this.clients.findByClientId(clientId);
		if (client == null || !client.getId().equals(authorization.getRegisteredClientId())) {
			throw invalidRequest();
		}
		OAuth2AuthorizationRequest request = authorization
			.getAttribute(OAuth2AuthorizationRequest.class.getName());
		if (request == null || !clientId.equals(request.getClientId())) {
			throw invalidRequest();
		}
		return new ConsentRequest(authorization, client, request);
	}

	private static Set<String> parseScopes(String scope) {
		if (scope == null || scope.isEmpty() || scope.length() > MAXIMUM_SCOPE_PARAMETER_LENGTH) {
			throw invalidRequest();
		}
		Set<String> scopes = new LinkedHashSet<>();
		for (String value : scope.split(" ", -1)) {
			if (value.isEmpty() || !scopes.add(value)) {
				throw invalidRequest();
			}
		}
		return Set.copyOf(scopes);
	}

	private static String render(ConsentView view) {
		StringBuilder requested = new StringBuilder();
		StringBuilder retained = new StringBuilder();
		int index = 0;
		for (String scope : view.requestedScopes().stream().sorted().toList()) {
			String escapedScope = HtmlUtils.htmlEscape(scope);
			if (OidcScopes.OPENID.equals(scope) || view.authorizedScopes().contains(scope)) {
				retained.append("<li><span class=\"status\">Approved</span><code>")
					.append(escapedScope)
					.append("</code></li>");
			}
			else {
				String id = "scope-" + index++;
				requested.append("<label class=\"scope\" for=\"")
					.append(id)
					.append("\"><input id=\"")
					.append(id)
					.append("\" type=\"checkbox\" name=\"scope\" value=\"")
					.append(escapedScope)
					.append("\"><code>")
					.append(escapedScope)
					.append("</code></label>");
			}
		}
		String retainedSection = retained.isEmpty() ? ""
				: "<section><h2>Already approved</h2><ul class=\"retained\">" + retained + "</ul></section>";
		return """
				<!doctype html>
				<html lang="en">
				<head>
				<meta charset="utf-8">
				<meta name="viewport" content="width=device-width,initial-scale=1">
				<title>Authorize access</title>
				<style>
				:root{color-scheme:light dark;font-family:system-ui,-apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif}*{box-sizing:border-box}body{margin:0;background:#f4f6f8;color:#17202a}main{min-height:100vh;display:grid;place-items:center;padding:24px}.panel{width:min(100%%,560px);background:#fff;border:1px solid #d8dee4;border-radius:8px;box-shadow:0 12px 32px rgba(23,32,42,.10);overflow:hidden}.heading{padding:28px 30px 22px;border-bottom:1px solid #e5e9ed}.eyebrow{margin:0 0 8px;color:#52606d;font-size:13px;font-weight:700;text-transform:uppercase}.heading h1{margin:0;font-size:25px;line-height:1.25;overflow-wrap:anywhere}.heading p{margin:12px 0 0;color:#52606d;line-height:1.5;overflow-wrap:anywhere}.content{padding:24px 30px 30px}h2{margin:0 0 12px;font-size:15px}code{min-width:0;overflow-wrap:anywhere}.scope{display:flex;align-items:center;gap:12px;min-width:0;padding:13px 14px;border:1px solid #c9d1d9;border-radius:6px;margin-bottom:10px;cursor:pointer}.scope:hover{border-color:#297a65;background:#f2faf7}.scope input{width:18px;height:18px;margin:0;flex:none;accent-color:#176b57}.retained{list-style:none;padding:0;margin:0 0 22px}.retained li{display:flex;justify-content:space-between;gap:12px;padding:8px 0;color:#52606d}.status{font-size:12px;color:#176b57;font-weight:700}.actions{display:flex;gap:10px;margin-top:24px}.actions button{min-height:42px;border-radius:6px;padding:0 18px;font:inherit;font-weight:700;cursor:pointer}.approve{border:1px solid #176b57;background:#176b57;color:#fff}.deny{border:1px solid #aab4be;background:transparent;color:#34404b}@media(max-width:520px){main{padding:0}.panel{min-height:100vh;border:0;border-radius:0;box-shadow:none}.heading,.content{padding-left:22px;padding-right:22px}.actions{flex-direction:column}.actions button{width:100%%}}@media(prefers-color-scheme:dark){body{background:#11161b;color:#e8edf2}.panel{background:#1b2229;border-color:#35404a}.heading{border-color:#35404a}.heading p,.eyebrow,.retained li{color:#acb8c3}.scope{border-color:#46535f}.scope:hover{background:#1c302a;border-color:#54b89d}.deny{color:#e8edf2;border-color:#64717d}}
				</style>
				</head>
				<body>
				<main><article class="panel" aria-labelledby="title">
				<header class="heading"><p class="eyebrow">Authorization request</p><h1 id="title">%s</h1><p><strong>%s</strong> is requesting access to account <strong>%s</strong>.</p></header>
				<form class="content" method="post" action="%s">
				<input type="hidden" name="client_id" value="%s">
				<input type="hidden" name="state" value="%s">
				%s
				<section><h2>Requested access</h2>%s</section>
				<div class="actions"><button class="approve" type="submit">Approve selected</button><button class="deny" type="submit" form="deny-consent">Deny</button></div>
				</form>
				<form id="deny-consent" method="post" action="%s">
				<input type="hidden" name="client_id" value="%s">
				<input type="hidden" name="state" value="%s">
				<input type="hidden" name="%s" value="%s">
				</form>
				</article></main>
				</body>
				</html>
				""".formatted(HtmlUtils.htmlEscape(view.clientName()), HtmlUtils.htmlEscape(view.clientId()),
				HtmlUtils.htmlEscape(view.principalName()), HtmlUtils.htmlEscape(view.authorizationEndpoint()),
				HtmlUtils.htmlEscape(view.clientId()), HtmlUtils.htmlEscape(view.state()), retainedSection, requested,
				HtmlUtils.htmlEscape(view.denialEndpoint()), HtmlUtils.htmlEscape(view.clientId()),
				HtmlUtils.htmlEscape(view.state()), HtmlUtils.htmlEscape(view.csrfParameter()),
				HtmlUtils.htmlEscape(view.csrfToken()));
	}

	private static ResponseStatusException invalidRequest() {
		return new ResponseStatusException(HttpStatus.BAD_REQUEST, "Invalid authorization consent request");
	}

	private record ConsentView(String clientName, String clientId, String principalName, String state,
			Set<String> requestedScopes, Set<String> authorizedScopes, String authorizationEndpoint,
			String denialEndpoint, String csrfParameter, String csrfToken) {
	}

	private record ConsentRequest(OAuth2Authorization authorization, RegisteredClient client,
			OAuth2AuthorizationRequest request) {
	}

}
