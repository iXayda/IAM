package com.ixayda.iam.account.internal;

import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Configuration;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(AccountMfaProperties.class)
class AccountMfaConfiguration {

}
