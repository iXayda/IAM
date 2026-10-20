package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityClient;

public record IdentityClientResponse(UUID id, IdentityClientConfigurationResponse configuration, IdentityClient.Status status,
		long version, Instant createdAt, Instant updatedAt, Instant secretRotatedAt) { }
