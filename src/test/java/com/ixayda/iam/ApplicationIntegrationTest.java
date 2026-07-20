package com.ixayda.iam;

import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;

@AutoConfigureMetrics
@Import(TestcontainersConfiguration.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = {
		"iam.authorization.server.issuer=https://issuer.example.test",
		"iam.authorization.server.service-token-audience=https://scim.example.test/scim/v2",
		"iam.authorization.server.admin-token-audience=https://admin.example.test/iam/admin",
		"iam.authorization.signing-key-protection.active-key-id=test-v1",
		"iam.authorization.signing-key-protection.keys.test-v1=AQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQEBAQE=",
		"iam.authorization.token-protection.active-key-id=test-v1",
		"iam.authorization.token-protection.keys.test-v1=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"iam.credential.totp-secret-protection.active-key-id=test-v1",
		"iam.credential.totp-secret-protection.keys.test-v1=AgICAgICAgICAgICAgICAgICAgICAgICAgICAgICAgI=",
		"iam.scim.base-url=https://scim.example.test/scim/v2",
		"iam.ratelimit.login.key-prefix=iam:test:ratelimit",
		"iam.ratelimit.login.key-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"iam.security-state.key-prefix=iam:test:security-state",
		"iam.security-state.key-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
		"management.metrics.tags.environment=test",
		"management.tracing.sampling.probability=1.0" })
public abstract class ApplicationIntegrationTest {

}
