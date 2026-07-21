package com.ixayda.iam.account.internal;

import java.net.URI;
import java.util.Arrays;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpSession;

import com.ixayda.iam.authorization.AuthorizationPrincipal;
import com.ixayda.iam.credential.TotpCodeAttempt;
import com.ixayda.iam.credential.TotpCredentialId;
import com.ixayda.iam.credential.TotpEnrollment;
import com.ixayda.iam.credential.TotpOperations;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.web.csrf.CsrfToken;
import org.springframework.web.bind.annotation.DeleteMapping;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RestController;

@RestController
final class AccountMfaController {

	private final TotpOperations totp;

	private final AccountTotpProvisioning provisioning;

	AccountMfaController(TotpOperations totp, AccountTotpProvisioning provisioning) {
		this.totp = totp;
		this.provisioning = provisioning;
	}

	@GetMapping(AccountMfaWebSecurityConfiguration.CSRF_PATH)
	ResponseEntity<AccountCsrfTokenResponse> csrf(HttpServletRequest request) {
		Object attribute = request.getAttribute(CsrfToken.class.getName());
		if (!(attribute instanceof CsrfToken token)) {
			throw new IllegalStateException("CSRF token is unavailable");
		}
		return noStore(new AccountCsrfTokenResponse(token.getHeaderName(), token.getParameterName(), token.getToken()));
	}

	@GetMapping(AccountMfaWebSecurityConfiguration.MFA_PATH)
	ResponseEntity<AccountMfaStatusResponse> status(@AuthenticationPrincipal AuthorizationPrincipal principal) {
		return noStore(new AccountMfaStatusResponse(
				this.totp.hasActiveCredential(principal.tenantId(), principal.userId())));
	}

	@PostMapping(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH)
	ResponseEntity<AccountTotpEnrollmentResponse> beginEnrollment(
			@AuthenticationPrincipal AuthorizationPrincipal principal) {
		try (TotpEnrollment enrollment = this.totp.beginEnrollment(principal.tenantId(), principal.userId())) {
			AccountTotpEnrollmentResponse response =
					this.provisioning.response(principal.tenantId(), principal.userId(), enrollment);
			URI location = URI.create(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH + "/"
					+ enrollment.credentialId());
			return ResponseEntity.created(location).cacheControl(CacheControl.noStore()).body(response);
		}
	}

	@PostMapping(AccountMfaWebSecurityConfiguration.TOTP_ENROLLMENTS_PATH + "/{credentialId}/activation")
	ResponseEntity<Void> activate(@AuthenticationPrincipal AuthorizationPrincipal principal,
			@PathVariable String credentialId, @RequestBody ActivateTotpRequest request, HttpServletRequest servletRequest) {
		if (request == null || request.code() == null) {
			return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
		}
		char[] code = request.code().toCharArray();
		TotpCredentialId parsedCredentialId;
		try {
			parsedCredentialId = TotpCredentialId.from(credentialId);
		}
		catch (IllegalArgumentException exception) {
			Arrays.fill(code, '\0');
			return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
		}
		TotpCodeAttempt attempt;
		try {
			attempt = new TotpCodeAttempt(code);
		}
		catch (IllegalArgumentException exception) {
			Arrays.fill(code, '\0');
			return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
		}
		try (attempt) {
			boolean activated = this.totp.activate(principal.tenantId(), principal.userId(),
					parsedCredentialId, attempt);
			if (!activated) {
				return ResponseEntity.badRequest().cacheControl(CacheControl.noStore()).build();
			}
			invalidate(servletRequest);
			return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
		}
		finally {
			Arrays.fill(code, '\0');
		}
	}

	@DeleteMapping(AccountMfaWebSecurityConfiguration.TOTP_PATH)
	ResponseEntity<Void> revoke(@AuthenticationPrincipal AuthorizationPrincipal principal,
			HttpServletRequest servletRequest) {
		if (this.totp.revokeActive(principal.tenantId(), principal.userId())) {
			invalidate(servletRequest);
		}
		return ResponseEntity.noContent().cacheControl(CacheControl.noStore()).build();
	}

	private static <T> ResponseEntity<T> noStore(T body) {
		return ResponseEntity.ok().cacheControl(CacheControl.noStore()).body(body);
	}

	private static void invalidate(HttpServletRequest request) {
		HttpSession session = request.getSession(false);
		if (session != null) {
			session.invalidate();
		}
	}

}
