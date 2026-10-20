package com.ixayda.iam.service;

import javax.sql.DataSource;

import com.ixayda.iam.repository.IdentityDatabaseAccessRepository;

import org.springframework.stereotype.Service;

/** Deployment admission check; ordinary Web authorization remains in the feature workflows. */
@Service
public class IdentityDatabaseAccess {

	private final IdentityDatabaseAccessRepository repository;

	IdentityDatabaseAccess(IdentityDatabaseAccessRepository repository) { this.repository = repository; }

	public static void requireMaintenanceOwner(DataSource dataSource) {
		IdentityDatabaseAccessRepository.requireMaintenanceOwner(dataSource);
	}

	/** Metadata from another schema cannot authorize a mutation of the resolved business relations. */
	public String requireMaintenanceSchema() {
		return this.repository.maintenanceSchema().orElseThrow(() -> new IllegalStateException("Maintenance requires a consistent, migrated business schema"));
	}

	public void requireRestrictedRuntime() {
		if (!this.repository.isRestrictedRuntime()) { throw new IllegalStateException("IAM runtime database identity has maintenance capabilities"); }
	}
}
