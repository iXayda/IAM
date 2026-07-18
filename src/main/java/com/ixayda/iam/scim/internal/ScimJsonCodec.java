package com.ixayda.iam.scim.internal;

import java.io.IOException;
import java.io.OutputStream;

import com.unboundid.scim2.common.utils.JsonUtils;
import org.springframework.stereotype.Component;
import tools.jackson.databind.json.JsonMapper;

@Component
final class ScimJsonCodec {

	private final JsonMapper jsonMapper = JsonUtils.createJsonMapper();

	JsonMapper jsonMapper() {
		return this.jsonMapper;
	}

	void write(OutputStream output, Object value) throws IOException {
		this.jsonMapper.writeValue(output, value);
	}

}
