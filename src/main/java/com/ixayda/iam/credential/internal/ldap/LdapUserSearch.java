package com.ixayda.iam.credential.internal.ldap;

import java.util.List;
import java.util.Objects;

import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.LoginKey;

@FunctionalInterface
interface LdapUserSearch {

	List<LdapUserCandidate> find(LoginKey loginKey);

}

record LdapUserCandidate(String absoluteDn, ExternalSubjectId subjectId) {

	LdapUserCandidate {
		if (absoluteDn == null || absoluteDn.isBlank()) {
			throw new IllegalArgumentException("LDAP user DN must not be blank");
		}
		Objects.requireNonNull(subjectId, "LDAP subject ID must not be null");
	}

	@Override
	public String toString() {
		return "LdapUserCandidate[redacted]";
	}

}

final class LdapDirectoryDataException extends RuntimeException {

	LdapDirectoryDataException() {
		super("LDAP directory entry is invalid");
	}

	LdapDirectoryDataException(Throwable cause) {
		super("LDAP directory entry is invalid", cause);
	}

}
