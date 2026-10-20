package com.ixayda.iam.dto;

import com.ixayda.iam.model.IdentityResource;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceSearchRequest(@Schema(description = "资源状态，区分大小写：ACTIVE、DISABLED") IdentityResource.Status status,
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页返回的 nextCursor，保持原状态条件") String cursor) { }
