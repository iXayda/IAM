package com.ixayda.iam.auth.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties({ LocalPasswordLoginProperties.class, MfaChallengeProperties.class })
class LocalPasswordLoginConfiguration {

	@Bean
	MfaChallengeTimeSource mfaChallengeTimeSource() {
		return new MfaChallengeTimeSource();
	}

}
