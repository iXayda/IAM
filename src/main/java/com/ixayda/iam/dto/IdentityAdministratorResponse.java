package com.ixayda.iam.dto;

import java.util.UUID;

public record IdentityAdministratorResponse(UUID id, String username, String displayName) { }
