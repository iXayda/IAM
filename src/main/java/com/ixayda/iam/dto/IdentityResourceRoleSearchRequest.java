package com.ixayda.iam.dto;

import com.ixayda.iam.model.IdentityResourceRole;

import io.swagger.v3.oas.annotations.media.Schema;

public record IdentityResourceRoleSearchRequest(@Schema(description = "角色状态，区分大小写：ACTIVE、DISABLED") IdentityResourceRole.Status status,
		@Schema(description = "每页数量", minimum = "1", maximum = "100", defaultValue = "20") Integer pageSize,
		@Schema(description = "上一页返回的 nextCursor，保持原所属资源和状态条件") String cursor) { }
