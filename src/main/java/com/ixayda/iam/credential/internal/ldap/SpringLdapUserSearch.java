package com.ixayda.iam.credential.internal.ldap;

import java.util.Base64;
import java.util.List;
import java.util.Objects;

import javax.naming.InvalidNameException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.ldap.LdapName;

import com.ixayda.iam.user.ExternalSubjectId;
import com.ixayda.iam.user.LoginKey;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.LdapQueryBuilder;
import org.springframework.ldap.query.SearchScope;

final class SpringLdapUserSearch implements LdapUserSearch {

	private final LdapClient client;

	private final LdapExternalCredentialSettings settings;

	SpringLdapUserSearch(LdapClient client, LdapExternalCredentialSettings settings) {
		this.client = Objects.requireNonNull(client, "LDAP client must not be null");
		this.settings = Objects.requireNonNull(settings, "LDAP settings must not be null");
	}

	@Override
	public List<LdapUserCandidate> find(LoginKey loginKey) {
		Objects.requireNonNull(loginKey, "Login key must not be null");
		LdapQuery query = LdapQueryBuilder.query()
			.base(this.settings.userSearchBase())
			.searchScope(SearchScope.SUBTREE)
			.countLimit(2)
			.attributes(this.settings.subjectAttribute())
			.where(this.settings.loginAttribute())
			.is(loginKey.canonicalValue());
		ContextMapper<LdapUserCandidate> mapper = this::mapCandidate;
		return this.client.search().query(query).map(mapper).list();
	}

	private LdapUserCandidate mapCandidate(Object source) throws javax.naming.NamingException {
		if (!(source instanceof DirContextOperations entry)) {
			throw new LdapDirectoryDataException();
		}
		String absoluteDn = entry.getNameInNamespace();
		if (absoluteDn == null || absoluteDn.isBlank()) {
			throw new LdapDirectoryDataException();
		}
		try {
			if (new LdapName(absoluteDn).isEmpty()) {
				throw new LdapDirectoryDataException();
			}
		}
		catch (InvalidNameException exception) {
			throw new LdapDirectoryDataException(exception);
		}

		Attributes attributes = entry.getAttributes();
		Attribute subject = attributes == null ? null : attributes.get(this.settings.subjectAttribute());
		if (subject == null || subject.size() != 1) {
			throw new LdapDirectoryDataException();
		}
		return new LdapUserCandidate(absoluteDn, subjectId(subject.get()));
	}

	private ExternalSubjectId subjectId(Object value) {
		try {
			return switch (this.settings.subjectFormat()) {
				case TEXT -> {
					if (!(value instanceof String text)) {
						throw new LdapDirectoryDataException();
					}
					yield ExternalSubjectId.from(text);
				}
				case BINARY_BASE64URL -> {
					if (!(value instanceof byte[] bytes) || bytes.length == 0) {
						throw new LdapDirectoryDataException();
					}
					yield ExternalSubjectId.from(Base64.getUrlEncoder().withoutPadding().encodeToString(bytes));
				}
			};
		}
		catch (IllegalArgumentException exception) {
			throw new LdapDirectoryDataException(exception);
		}
	}

}
