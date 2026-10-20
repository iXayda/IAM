package com.ixayda.iam;

import java.time.Duration;

import com.zaxxer.hikari.HikariDataSource;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.jdbc.core.ConnectionCallback;

import static org.assertj.core.api.Assertions.*;
import static org.awaitility.Awaitility.await;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.NONE, properties = {
		"spring.datasource.hikari.maximum-pool-size=2", "spring.datasource.hikari.minimum-idle=0",
		"spring.datasource.hikari.data-source-properties.ApplicationName=iam-restore-test-pool" })
public abstract class IdentityRestoreTestSupport extends IdentityProtocolTestSupport {

	@Autowired protected HikariDataSource dataSource;

	protected void evictPoolConnections() {
		this.dataSource.getHikariPoolMXBean().softEvictConnections();
		this.template.execute((ConnectionCallback<Void>) connection -> {
			assertThat(connection.getAutoCommit()).as("Pool draining must run outside a transaction").isTrue();
			// Hikari removes entries before asynchronously closing their physical connections.
			// Hold one replacement connection and wait only for this pool, leaving external clients for the real offline check.
			try (var statement = connection.createStatement()) {
				await().alias("evicted restore-test database connections to close")
						.pollInSameThread().pollDelay(Duration.ZERO).pollInterval(Duration.ofMillis(10)).atMost(Duration.ofSeconds(5))
						.until(() -> {
							try (var result = statement.executeQuery("""
									SELECT NOT EXISTS (SELECT 1 FROM pg_stat_activity
									    WHERE datname=current_database() AND pid<>pg_backend_pid()
									        AND backend_type='client backend' AND application_name=current_setting('application_name'))
									""")) {
								result.next(); return result.getBoolean(1);
							}
						});
			}
			return null;
		});
	}

}
