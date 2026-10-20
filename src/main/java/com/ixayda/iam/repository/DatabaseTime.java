package com.ixayda.iam.repository;

import java.time.Instant;
import java.time.InstantSource;
import java.time.OffsetDateTime;

import org.springframework.jdbc.core.simple.JdbcClient;
import org.springframework.stereotype.Repository;

/** Login, MFA and authorization interaction times must be comparable across application instances. */
@Repository
class DatabaseTime implements InstantSource {

	private final JdbcClient jdbc;

	DatabaseTime(JdbcClient jdbc) { this.jdbc = jdbc; }

	@Override
	public Instant instant() {
		return this.jdbc.sql("SELECT clock_timestamp()").query(OffsetDateTime.class).single().toInstant();
	}

}
