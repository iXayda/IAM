package com.ixayda.iam.security;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.ProviderManager;

@Configuration(proxyBeanMethods = false)
public class PasswordAuthenticationConfiguration {

	@Bean
	AuthenticationManager authenticationManager(IdentityPasswordAuthenticationProvider provider) {
		return new ProviderManager(provider);
	}

}
