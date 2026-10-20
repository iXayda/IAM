package com.ixayda.iam.service;

import com.ixayda.iam.repository.IdentityDatabaseAccessRepository;

import org.springframework.stereotype.Service;

/** Deployment admission check; ordinary Web authorization remains in the feature workflows. */
@Service
public class IdentityDatabaseAccess {

	private final IdentityDatabaseAccessRepository repository;

	IdentityDatabaseAccess(IdentityDatabaseAccessRepository repository) { this.repository = repository; }

	public void requireRestrictedRuntime() {
		if (!this.repository.isRestrictedRuntime()) { throw new IllegalStateException("IAM runtime database identity has maintenance capabilities"); }
	}
}
