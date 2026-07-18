package com.ixayda.iam.scim.internal;

import org.springframework.context.annotation.Configuration;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.http.converter.HttpMessageConverters;
import org.springframework.web.servlet.config.annotation.WebMvcConfigurer;

@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(ScimProperties.class)
class ScimWebMvcConfiguration implements WebMvcConfigurer {

	private final ScimJsonCodec codec;

	ScimWebMvcConfiguration(ScimJsonCodec codec) {
		this.codec = codec;
	}

	@Override
	public void configureMessageConverters(HttpMessageConverters.ServerBuilder builder) {
		builder.configureMessageConvertersList(
				(converters) -> converters.add(0, new ScimJsonHttpMessageConverter(this.codec)));
	}

}
