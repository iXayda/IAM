package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityUser;

public record IdentityUserResponse(UUID id, String username, String displayName, IdentityUser.Status status, Instant createdAt) { }
