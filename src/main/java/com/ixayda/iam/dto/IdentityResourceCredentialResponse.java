package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.UUID;

import com.ixayda.iam.model.IdentityResourceCredential;

/** Deliberately excludes both the plaintext secret and its stored hash. */
public record IdentityResourceCredentialResponse(UUID resourceId, IdentityResourceCredential.Status status, long version,
		Instant createdAt, Instant rotatedAt, Instant updatedAt) { }
