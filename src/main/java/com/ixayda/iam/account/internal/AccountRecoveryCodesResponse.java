package com.ixayda.iam.account.internal;

import java.util.List;
import java.util.Objects;

final class AccountRecoveryCodesResponse {

	private final List<String> codes;

	AccountRecoveryCodesResponse(List<String> codes) {
		Objects.requireNonNull(codes, "Recovery codes must not be null");
		this.codes = List.copyOf(codes);
	}

	public List<String> getCodes() {
		return this.codes;
	}

	@Override
	public String toString() {
		return "AccountRecoveryCodesResponse[count=" + this.codes.size() + ", codes=redacted]";
	}

}
