package com.ixayda.iam.dto;

import java.time.Instant;
import java.util.List;
import java.util.UUID;

/** Frontend display facts contain no original protocol secrets or completion authority. */
public record IdentityAuthorizationInteractionResponse(UUID clientId, String clientName, List<String> scopes, Instant expiresAt,
		UUID subject, boolean loginRequired, boolean selectionRequired, boolean consentRequired) { }
