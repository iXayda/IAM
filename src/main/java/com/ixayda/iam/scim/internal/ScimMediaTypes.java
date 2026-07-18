package com.ixayda.iam.scim.internal;

import com.unboundid.scim2.common.utils.ApiConstants;
import org.springframework.http.MediaType;

final class ScimMediaTypes {

	static final String SCIM_JSON_VALUE = ApiConstants.MEDIA_TYPE_SCIM;

	static final MediaType SCIM_JSON = MediaType.parseMediaType(SCIM_JSON_VALUE);

	private ScimMediaTypes() {
	}

}
