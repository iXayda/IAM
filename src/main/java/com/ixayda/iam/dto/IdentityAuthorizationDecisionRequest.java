package com.ixayda.iam.dto;

import io.swagger.v3.oas.annotations.media.Schema;

@Schema(additionalProperties = Schema.AdditionalPropertiesValue.FALSE)
public record IdentityAuthorizationDecisionRequest(
		@Schema(requiredMode = Schema.RequiredMode.REQUIRED, allowableValues = { "continue", "cancel" }, description = "确认当前账号与已展示的请求范围，或取消本次授权") String decision) { }
