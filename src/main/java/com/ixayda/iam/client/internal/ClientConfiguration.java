package com.ixayda.iam.client.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ClientSecretProperties.class)
class ClientConfiguration {
}
