package com.ixayda.iam.audit.internal;

import io.micrometer.core.instrument.MeterRegistry;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.scheduling.annotation.EnableScheduling;

@Configuration(proxyBeanMethods = false)
@EnableScheduling
@EnableConfigurationProperties(AuditRetentionProperties.class)
class AuditEventConfiguration {

	@Bean
	AuditEventJsonCodec auditEventJsonCodec() {
		return new AuditEventJsonCodec();
	}

	@Bean
	AuditRetentionObserver auditRetentionObserver(JdbcAuditEventRepository repository,
			AuditRetentionProperties properties, MeterRegistry meterRegistry) {
		return new AuditRetentionObserver(repository, properties, meterRegistry);
	}

}
