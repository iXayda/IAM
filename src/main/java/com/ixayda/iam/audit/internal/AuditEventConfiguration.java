package com.ixayda.iam.audit.internal;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
class AuditEventConfiguration {

	@Bean
	AuditEventJsonCodec auditEventJsonCodec() {
		return new AuditEventJsonCodec();
	}

}
