package com.ixayda.iam.securitystate;

import java.util.Objects;

import com.ixayda.iam.tenant.TenantId;

/**
 * Tenant-scoped purpose and opaque subject binding for one-time security state.
 * Bindings should use stable internal identifiers rather than login names or contact
 * details.
 */
public record SecurityStateKey(TenantId tenantId, String purpose, String binding) {

	public static final int MAXIMUM_PURPOSE_LENGTH = 64;

	public static final int MAXIMUM_BINDING_LENGTH = 256;

	public SecurityStateKey {
		Objects.requireNonNull(tenantId, "Tenant ID must not be null");
		purpose = validatePurpose(purpose);
		binding = validateBinding(binding);
	}

	@Override
	public String toString() {
		return "SecurityStateKey[tenantId=" + this.tenantId + ", purpose=" + this.purpose + ", binding=redacted]";
	}

	private static String validatePurpose(String value) {
		Objects.requireNonNull(value, "Security state purpose must not be null");
		if (value.isEmpty() || value.length() > MAXIMUM_PURPOSE_LENGTH || !isLowercaseLetter(value.charAt(0))
				|| !value.chars().allMatch(SecurityStateKey::isPurposeCharacter)) {
			throw new IllegalArgumentException(
					"Security state purpose must start with a lowercase letter and contain at most 64 lowercase letters, digits, dots, underscores, or hyphens");
		}
		return value;
	}

	private static String validateBinding(String value) {
		Objects.requireNonNull(value, "Security state binding must not be null");
		if (value.isEmpty() || value.length() > MAXIMUM_BINDING_LENGTH
				|| !value.chars().allMatch(character -> character >= 0x21 && character <= 0x7e)) {
			throw new IllegalArgumentException(
					"Security state binding must contain 1 to 256 visible ASCII characters");
		}
		return value;
	}

	private static boolean isPurposeCharacter(int character) {
		return isLowercaseLetter(character) || character >= '0' && character <= '9' || character == '.'
				|| character == '_' || character == '-';
	}

	private static boolean isLowercaseLetter(int character) {
		return character >= 'a' && character <= 'z';
	}

}
