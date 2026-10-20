package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentitySigningKeys;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
public class IdentitySigningConfiguration {

	@Bean
	IdentityJwtEncoder identityJwtEncoder(IdentitySigningKeys keys) { return new IdentityJwtEncoder(keys); }

	@Bean
	IdentityJwkSource identityJwkSource(IdentitySigningKeys keys) { return new IdentityJwkSource(keys); }

	@Bean
	@Lazy(false)
	@DependsOnDatabaseInitialization
	SmartInitializingSingleton signingKeyInitializer(IdentitySigningKeys keys) {
		// Non-Web administrator commands do not need signing components; Web startup must load them.
		// A runner executes after the web server has started; this callback precedes lifecycle start.
		return keys::initialize;
	}

}
