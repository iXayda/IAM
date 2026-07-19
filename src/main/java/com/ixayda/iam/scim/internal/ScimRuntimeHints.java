package com.ixayda.iam.scim.internal;

import java.util.List;

import com.unboundid.scim2.common.BaseScimResource;
import com.unboundid.scim2.common.messages.ErrorResponse;
import com.unboundid.scim2.common.messages.ListResponse;
import com.unboundid.scim2.common.types.Address;
import com.unboundid.scim2.common.types.AttributeDefinition;
import com.unboundid.scim2.common.types.AuthenticationScheme;
import com.unboundid.scim2.common.types.BulkConfig;
import com.unboundid.scim2.common.types.ChangePasswordConfig;
import com.unboundid.scim2.common.types.ETagConfig;
import com.unboundid.scim2.common.types.Email;
import com.unboundid.scim2.common.types.Entitlement;
import com.unboundid.scim2.common.types.FilterConfig;
import com.unboundid.scim2.common.types.Group;
import com.unboundid.scim2.common.types.GroupResource;
import com.unboundid.scim2.common.types.InstantMessagingAddress;
import com.unboundid.scim2.common.types.Meta;
import com.unboundid.scim2.common.types.Member;
import com.unboundid.scim2.common.types.Name;
import com.unboundid.scim2.common.types.PaginationConfig;
import com.unboundid.scim2.common.types.PatchConfig;
import com.unboundid.scim2.common.types.PhoneNumber;
import com.unboundid.scim2.common.types.Photo;
import com.unboundid.scim2.common.types.ResourceTypeResource;
import com.unboundid.scim2.common.types.Role;
import com.unboundid.scim2.common.types.SchemaResource;
import com.unboundid.scim2.common.types.ServiceProviderConfigResource;
import com.unboundid.scim2.common.types.SortConfig;
import com.unboundid.scim2.common.types.UserResource;
import com.unboundid.scim2.common.types.X509Certificate;
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
			UserResource.class, GroupResource.class, Member.class, ScimUserCreateResource.class, Name.class, Email.class,
			PhoneNumber.class, Address.class,
			InstantMessagingAddress.class, Photo.class, Group.class, Entitlement.class, Role.class,
			X509Certificate.class, StatusSerializer.class, StatusDeserializer.class);

	@Override
	public void registerHints(RuntimeHints hints, ClassLoader classLoader) {
		for (Class<?> type : RESPONSE_TYPES) {
			hints.reflection()
				.registerType(type, MemberCategory.ACCESS_DECLARED_FIELDS, MemberCategory.INVOKE_DECLARED_CONSTRUCTORS,
						MemberCategory.INVOKE_PUBLIC_METHODS);
		}
	}

}
