package com.ixayda.iam.authorization.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ AuthorizationPersistenceProperties.class,
		AuthorizationTokenProtectionProperties.class })
class AuthorizationPersistenceConfiguration {

	@Bean
	AuthorizationTokenCipher authorizationTokenCipher(AuthorizationTokenProtectionProperties properties) {
		return new AuthorizationTokenCipher(properties);
	}

	@Bean
	AuthorizationJsonCodec authorizationJsonCodec() {
		return new AuthorizationJsonCodec();
	}

	@Bean
	AuthorizationSnapshotMapper authorizationSnapshotMapper(AuthorizationJsonCodec jsonCodec) {
		return new AuthorizationSnapshotMapper(jsonCodec);
	}

	@Bean
	OAuth2AuthorizationService oauth2AuthorizationService(JdbcClient jdbcClient, AuthorizationSnapshotMapper mapper,
			AuthorizationTokenCipher tokenCipher, AuthorizationPersistenceProperties properties) {
		return new JdbcOAuth2AuthorizationService(jdbcClient, mapper, tokenCipher, properties);
	}

	@Bean
	OAuth2AuthorizationConsentService oauth2AuthorizationConsentService(JdbcClient jdbcClient) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcClient);
	}

}
