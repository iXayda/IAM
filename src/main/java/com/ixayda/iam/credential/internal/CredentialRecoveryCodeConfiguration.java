package com.ixayda.iam.credential.internal;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class CredentialRecoveryCodeConfiguration {

	@Bean
	RecoveryCodeGenerator recoveryCodeGenerator() {
		return new RecoveryCodeGenerator();
	}

	@Bean
	RecoveryCodeTimeSource recoveryCodeTimeSource() {
		return new RecoveryCodeTimeSource();
	}

}
