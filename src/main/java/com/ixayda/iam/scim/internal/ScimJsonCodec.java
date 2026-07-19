package com.ixayda.iam.scim.internal;

import java.io.IOException;
import java.io.OutputStream;

import com.unboundid.scim2.common.utils.JsonUtils;
import org.springframework.stereotype.Component;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.MapperFeature;
import tools.jackson.databind.cfg.CoercionAction;
import tools.jackson.databind.cfg.CoercionInputShape;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.type.LogicalType;

@Component
final class ScimJsonCodec {

	private final JsonMapper jsonMapper = createJsonMapper();

	JsonMapper jsonMapper() {
		return this.jsonMapper;
	}

	void write(OutputStream output, Object value) throws IOException {
		this.jsonMapper.writeValue(output, value);
	}

	private static JsonMapper createJsonMapper() {
		return JsonUtils.createJsonMapper().rebuild()
			.enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
			.disable(MapperFeature.ALLOW_COERCION_OF_SCALARS)
			.withCoercionConfig(LogicalType.Textual, (coercion) -> {
				coercion.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
				coercion.setCoercion(CoercionInputShape.Float, CoercionAction.Fail);
				coercion.setCoercion(CoercionInputShape.Boolean, CoercionAction.Fail);
			})
			.withCoercionConfig(LogicalType.Boolean, (coercion) -> {
				coercion.setCoercion(CoercionInputShape.String, CoercionAction.Fail);
				coercion.setCoercion(CoercionInputShape.EmptyString, CoercionAction.Fail);
				coercion.setCoercion(CoercionInputShape.Integer, CoercionAction.Fail);
				coercion.setCoercion(CoercionInputShape.Float, CoercionAction.Fail);
			})
			.build();
	}

}
