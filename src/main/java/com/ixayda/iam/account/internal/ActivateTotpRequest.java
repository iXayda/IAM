package com.ixayda.iam.account.internal;

record ActivateTotpRequest(String code) {

	@Override
	public String toString() {
		return "ActivateTotpRequest[code=redacted]";
	}

}
