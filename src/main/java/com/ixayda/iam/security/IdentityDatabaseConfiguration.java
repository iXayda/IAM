package com.ixayda.iam.security;

import com.ixayda.iam.service.IdentityDatabaseAccess;

import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.autoconfigure.condition.ConditionalOnWebApplication;
import org.springframework.boot.sql.init.dependency.DependsOnDatabaseInitialization;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Lazy;

@Configuration(proxyBeanMethods = false)
@ConditionalOnWebApplication(type = ConditionalOnWebApplication.Type.SERVLET)
@ConditionalOnProperty(name = "iam.database.restricted-runtime", havingValue = "true")
public class IdentityDatabaseConfiguration {

	@Bean
	@Lazy(false)
	@DependsOnDatabaseInitialization
	SmartInitializingSingleton runtimeDatabaseInitializer(IdentityDatabaseAccess access) {
		return access::requireRestrictedRuntime;
	}
}
