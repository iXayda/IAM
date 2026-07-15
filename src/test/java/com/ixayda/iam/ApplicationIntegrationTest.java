package com.ixayda.iam;

import org.springframework.boot.micrometer.metrics.test.autoconfigure.AutoConfigureMetrics;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.SpringBootTest.WebEnvironment;
import org.springframework.context.annotation.Import;

@AutoConfigureMetrics
@Import(TestcontainersConfiguration.class)
@SpringBootTest(webEnvironment = WebEnvironment.RANDOM_PORT, properties = {
		"iam.ratelimit.login.key-prefix=iam:test:ratelimit",
		"iam.ratelimit.login.key-secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=" })
public abstract class ApplicationIntegrationTest {

}
