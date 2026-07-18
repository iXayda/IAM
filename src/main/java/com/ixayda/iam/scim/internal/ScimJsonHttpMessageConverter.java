package com.ixayda.iam.scim.internal;

import java.util.List;

import com.unboundid.scim2.common.BaseScimResource;
import org.springframework.core.ResolvableType;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.JacksonJsonHttpMessageConverter;

final class ScimJsonHttpMessageConverter extends JacksonJsonHttpMessageConverter {

	ScimJsonHttpMessageConverter(ScimJsonCodec codec) {
		super(codec.jsonMapper());
		setSupportedMediaTypes(List.of(ScimMediaTypes.SCIM_JSON, MediaType.APPLICATION_JSON));
	}

	@Override
	public boolean canRead(ResolvableType type, MediaType mediaType) {
		return isScimResource(type) && super.canRead(type, mediaType);
	}

	@Override
	public boolean canWrite(ResolvableType type, Class<?> contextClass, MediaType mediaType) {
		return isScimResource(type) && super.canWrite(type, contextClass, mediaType);
	}

	private static boolean isScimResource(ResolvableType type) {
		Class<?> rawType = type.resolve();
		return rawType != null && BaseScimResource.class.isAssignableFrom(rawType);
	}

}
