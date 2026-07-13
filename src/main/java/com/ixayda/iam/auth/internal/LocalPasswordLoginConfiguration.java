package com.ixayda.iam.auth.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LocalPasswordLoginProperties.class)
class LocalPasswordLoginConfiguration {
}
