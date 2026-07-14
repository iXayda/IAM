package com.ixayda.iam.credential.internal.ldap;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.net.URI;
import java.time.Duration;
import java.util.List;
import java.util.Set;

import javax.naming.directory.BasicAttribute;
import javax.naming.directory.BasicAttributes;

import com.ixayda.iam.tenant.TenantId;
import com.ixayda.iam.user.ExternalIdentityProviderId;
import com.ixayda.iam.user.LoginKey;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.ldap.core.ContextMapper;
import org.springframework.ldap.core.DirContextOperations;
import org.springframework.ldap.core.LdapClient;
import org.springframework.ldap.query.LdapQuery;
import org.springframework.ldap.query.SearchScope;

class SpringLdapUserSearchTests {

	private static final LoginKey LOGIN_KEY = LoginKey.from("alice");

	private static final String USER_DN = "uid=alice,ou=people,dc=example,dc=test";

	private static final String SUBJECT_ID = "8d86b38a-9e5e-4d4d-a08d-9cb9086a5932";

	private final LdapClient client = mock(LdapClient.class);

	private final LdapClient.SearchSpec searchSpec = mock(LdapClient.SearchSpec.class);

	private final LdapClient.MappedSearchSpec<LdapUserCandidate> mappedSearch = mock();

	@BeforeEach
	@SuppressWarnings({ "rawtypes", "unchecked" })
	void configureClient() {
		when(this.client.search()).thenReturn(this.searchSpec);
		when(this.searchSpec.query(any(LdapQuery.class))).thenReturn(this.searchSpec);
		doReturn(this.mappedSearch).when(this.searchSpec).map(any(ContextMapper.class));
		when(this.mappedSearch.list()).thenReturn(List.of());
	}

	@Test
	void buildsAnEscapedSubtreeQueryReturningOnlyTheSubjectAttribute() {
		SpringLdapUserSearch search = new SpringLdapUserSearch(this.client, settings(LdapSubjectFormat.TEXT));
		LoginKey filterInjection = LoginKey.from("alice*)(uid=*)@example.test");

		assertThat(search.find(filterInjection)).isEmpty();

		ArgumentCaptor<LdapQuery> queryCaptor = ArgumentCaptor.forClass(LdapQuery.class);
		verify(this.searchSpec).query(queryCaptor.capture());
		LdapQuery query = queryCaptor.getValue();
		assertThat(query.base().toString()).isEqualTo("ou=people");
		assertThat(query.searchScope()).isEqualTo(SearchScope.SUBTREE);
		assertThat(query.countLimit()).isEqualTo(2);
		assertThat(query.attributes()).containsExactly("entryUUID");
		assertThat(query.filter().encode())
			.isEqualTo("(uid=alice\\2a\\29\\28uid=\\2a\\29@example.test)");
	}

	@Test
	void mapsTheAbsoluteDnAndConfiguredTextSubject() throws Exception {
		ContextMapper<LdapUserCandidate> mapper = mapper(settings(LdapSubjectFormat.TEXT));
		BasicAttributes attributes = new BasicAttributes(true);
		attributes.put("entryUUID", SUBJECT_ID);
		attributes.put("mail", "alice@example.test");

		LdapUserCandidate candidate = mapper.mapFromContext(entry(USER_DN, attributes));

		assertThat(candidate.absoluteDn()).isEqualTo(USER_DN);
		assertThat(candidate.subjectId().value()).isEqualTo(SUBJECT_ID);
		assertThat(candidate.toString()).isEqualTo("LdapUserCandidate[redacted]")
			.doesNotContain(USER_DN, SUBJECT_ID);
	}

	@Test
	void encodesBinarySubjectsAsUnpaddedBase64Url() throws Exception {
		ContextMapper<LdapUserCandidate> mapper = mapper(settings(LdapSubjectFormat.BINARY_BASE64URL));
		BasicAttributes attributes = new BasicAttributes(true);
		attributes.put("entryUUID", new byte[] { (byte) 0xfb, (byte) 0xff, 0x00 });

		LdapUserCandidate candidate = mapper.mapFromContext(entry(USER_DN, attributes));

		assertThat(candidate.subjectId().value()).isEqualTo("-_8A").doesNotContain("=");
	}

	@Test
	void rejectsMissingMultivaluedOrInvalidSubjectsAsDirectoryDataFailures() {
		ContextMapper<LdapUserCandidate> mapper = mapper(settings(LdapSubjectFormat.TEXT));
		BasicAttributes missing = new BasicAttributes(true);
		BasicAttributes multivalued = new BasicAttributes(true);
		BasicAttribute subjects = new BasicAttribute("entryUUID");
		subjects.add(SUBJECT_ID);
		subjects.add("another-subject");
		multivalued.put(subjects);
		BasicAttributes invalid = new BasicAttributes(true);
		invalid.put("entryUUID", "subject with spaces");

		assertThatThrownBy(() -> mapper.mapFromContext(entry(USER_DN, missing)))
			.isInstanceOf(LdapDirectoryDataException.class);
		assertThatThrownBy(() -> mapper.mapFromContext(entry(USER_DN, multivalued)))
			.isInstanceOf(LdapDirectoryDataException.class);
		assertThatThrownBy(() -> mapper.mapFromContext(entry(USER_DN, invalid)))
			.isInstanceOf(LdapDirectoryDataException.class);
		assertThatThrownBy(() -> mapper.mapFromContext(entry("uid=alice,broken", validAttributes())))
			.isInstanceOf(LdapDirectoryDataException.class);
	}

	@Test
	void requiresBinaryValuesForBinarySubjectConfiguration() {
		ContextMapper<LdapUserCandidate> mapper = mapper(settings(LdapSubjectFormat.BINARY_BASE64URL));
		BasicAttributes text = new BasicAttributes(true);
		text.put("entryUUID", SUBJECT_ID);
		BasicAttributes empty = new BasicAttributes(true);
		empty.put("entryUUID", new byte[0]);

		assertThatThrownBy(() -> mapper.mapFromContext(entry(USER_DN, text)))
			.isInstanceOf(LdapDirectoryDataException.class);
		assertThatThrownBy(() -> mapper.mapFromContext(entry(USER_DN, empty)))
			.isInstanceOf(LdapDirectoryDataException.class);
	}

	@SuppressWarnings({ "rawtypes", "unchecked" })
	private ContextMapper<LdapUserCandidate> mapper(LdapExternalCredentialSettings settings) {
		SpringLdapUserSearch search = new SpringLdapUserSearch(this.client, settings);
		search.find(LOGIN_KEY);
		ArgumentCaptor<ContextMapper<LdapUserCandidate>> mapperCaptor = ArgumentCaptor.forClass(ContextMapper.class);
		verify(this.searchSpec).map(mapperCaptor.capture());
		return mapperCaptor.getValue();
	}

	private static DirContextOperations entry(String dn, BasicAttributes attributes) {
		DirContextOperations entry = mock(DirContextOperations.class);
		when(entry.getNameInNamespace()).thenReturn(dn);
		when(entry.getAttributes()).thenReturn(attributes);
		return entry;
	}

	private static BasicAttributes validAttributes() {
		BasicAttributes attributes = new BasicAttributes(true);
		attributes.put("entryUUID", SUBJECT_ID);
		return attributes;
	}

	private static LdapExternalCredentialSettings settings(LdapSubjectFormat subjectFormat) {
		return new LdapExternalCredentialSettings(true, ExternalIdentityProviderId.from("corporate"),
				Set.of(TenantId.DEFAULT), List.of(URI.create("ldaps://directory.example.test:636")), "ou=people",
				"uid", "entryUUID", subjectFormat, LdapTransportSecurity.LDAPS, Duration.ofSeconds(3),
				Duration.ofSeconds(5));
	}

}
