package com.ixayda.iam.authorization.internal;

import java.util.ArrayList;

import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.source.ImmutableJWKSet;
import com.nimbusds.jose.jwk.source.JWKSource;
import com.nimbusds.jose.proc.SecurityContext;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.JwtEncoder;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtEncoder;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationConsentService;
import org.springframework.security.oauth2.server.authorization.settings.AuthorizationServerSettings;
import org.springframework.security.oauth2.server.authorization.token.JwtEncodingContext;
import org.springframework.security.oauth2.server.authorization.token.OAuth2TokenCustomizer;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ AuthorizationPersistenceProperties.class,
		AuthorizationServerProperties.class, AuthorizationSigningKeyProtectionProperties.class,
		AuthorizationTokenProtectionProperties.class })
class AuthorizationPersistenceConfiguration {

	@Bean
	AuthorizationTokenCipher authorizationTokenCipher(AuthorizationTokenProtectionProperties properties) {
		return new AuthorizationTokenCipher(properties);
	}

	@Bean
	AuthorizationSigningKeyCipher authorizationSigningKeyCipher(
			AuthorizationSigningKeyProtectionProperties properties) {
		return new AuthorizationSigningKeyCipher(properties);
	}

	@Bean
	AuthorizationSigningKeyAttestation authorizationSigningKeyAttestation(
			AuthorizationSigningKeyProtectionProperties properties) {
		return new AuthorizationSigningKeyAttestation(properties);
	}

	@Bean
	AuthorizationSigningKeyCodec authorizationSigningKeyCodec(AuthorizationSigningKeyCipher cipher,
			AuthorizationSigningKeyAttestation attestation) {
		return new AuthorizationSigningKeyCodec(cipher, attestation);
	}

	@Bean
	@DependsOnDatabaseInitialization
	AuthorizationSigningKeyRing authorizationSigningKeyRing(AuthorizationSigningKeyInitializer initializer) {
		return initializer.initialize();
	}

	@Bean
	JWKSource<SecurityContext> authorizationJwkSource(AuthorizationSigningKeyRing keyRing) {
		return new ImmutableJWKSet<>(new JWKSet(new ArrayList<JWK>(keyRing.publishedKeys())));
	}

	@Bean
	JwtEncoder authorizationJwtEncoder(AuthorizationSigningKeyRing keyRing) {
		JWKSource<SecurityContext> activeKey =
				new ImmutableJWKSet<>(new JWKSet(keyRing.activeSigningKey()));
		return new NimbusJwtEncoder(activeKey);
	}

	@Bean
	JwtDecoder authorizationJwtDecoder(JWKSource<SecurityContext> jwkSource,
			AuthorizationServerProperties properties) {
		NimbusJwtDecoder decoder = NimbusJwtDecoder.withJwkSource(jwkSource)
			.jwsAlgorithm(SignatureAlgorithm.RS256)
			.build();
		decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(properties.issuer().toASCIIString()));
		return decoder;
	}

	@Bean
	AuthorizationServerSettings authorizationServerSettings(AuthorizationServerProperties properties) {
		return AuthorizationServerSettings.builder().issuer(properties.issuer().toASCIIString()).build();
	}

	@Bean
	OAuth2TokenCustomizer<JwtEncodingContext> authorizationJwtCustomizer(AuthorizationServerProperties properties) {
		return new ServiceTokenJwtCustomizer(properties.serviceTokenAudience());
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
	JdbcOAuth2AuthorizationService oauth2AuthorizationService(JdbcClient jdbcClient, AuthorizationSnapshotMapper mapper,
			AuthorizationTokenCipher tokenCipher, AuthorizationPersistenceProperties properties) {
		return new JdbcOAuth2AuthorizationService(jdbcClient, mapper, tokenCipher, properties);
	}

	@Bean
	OAuth2AuthorizationConsentService oauth2AuthorizationConsentService(JdbcClient jdbcClient) {
		return new JdbcOAuth2AuthorizationConsentService(jdbcClient);
	}

}
