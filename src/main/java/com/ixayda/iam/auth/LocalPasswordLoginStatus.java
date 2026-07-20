package com.ixayda.iam.auth;

public enum LocalPasswordLoginStatus {

	AUTHENTICATED,

	MFA_REQUIRED,

	REJECTED,

	THROTTLED,

	UNAVAILABLE

}
