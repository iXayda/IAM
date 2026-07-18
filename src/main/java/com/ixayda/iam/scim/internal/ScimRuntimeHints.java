package com.ixayda.iam.scim.internal;

import java.util.List;

import com.unboundid.scim2.common.BaseScimResource;
import com.unboundid.scim2.common.messages.ErrorResponse;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.AttributeDefinition;
import com.unboundid.scim2.common.types.AuthenticationScheme;
import com.unboundid.scim2.common.types.BulkConfig;
import com.unboundid.scim2.common.types.ChangePasswordConfig;
import com.unboundid.scim2.common.types.ETagConfig;
import com.unboundid.scim2.common.types.FilterConfig;
import com.unboundid.scim2.common.types.Meta;
import com.unboundid.scim2.common.types.PaginationConfig;
import com.unboundid.scim2.common.types.PatchConfig;
import com.unboundid.scim2.common.types.ResourceTypeResource;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.ServiceProviderConfigResource;
import com.unboundid.scim2.common.types.SortConfig;
import com.unboundid.scim2.common.utils.StatusDeserializer;
import com.unboundid.scim2.common.utils.StatusSerializer;
import org.springframework.aot.hint.MemberCategory;
import org.springframework.aot.hint.RuntimeHints;
import org.springframework.aot.hint.RuntimeHintsRegistrar;

final class ScimRuntimeHints implements RuntimeHintsRegistrar {

	private static final List<Class<?>> RESPONSE_TYPES = List.of(BaseScimResource.class,
			ServiceProviderConfigResource.class, PatchConfig.class, BulkConfig.class, FilterConfig.class,
			ChangePasswordConfig.class, SortConfig.class, ETagConfig.class, PaginationConfig.class,
			AuthenticationScheme.class, ListResponse.class, SchemaResource.class, ResourceTypeResource.class,
			ResourceTypeResource.SchemaExtension.class, AttributeDefinition.class, Meta.class, ErrorResponse.class,
			StatusSerializer.class, StatusDeserializer.class);

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		for (Class<?> type : RESPONSE_TYPES) {
			hints.reflection()
				.registerType(type, MemberCategory.ACCESS_DECLARED_FIELDS, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
						MemberCategory.INVOKE_PUBLIC_METHODS);
		}
	}

}
