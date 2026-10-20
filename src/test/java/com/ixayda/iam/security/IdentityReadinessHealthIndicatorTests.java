package com.ixayda.iam.security;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;

import com.ixayda.iam.service.IdentityReadiness;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.health.contributor.Status;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import static org.assertj.core.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(OutputCaptureExtension.class)
class IdentityReadinessHealthIndicatorTests {

	@Test
	void concurrentProbesFailFastWithoutLaunchingMoreChecksOrWaitingBehindBlockedWork() throws Exception {
		var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var calls = new AtomicInteger();
		var readiness = mock(IdentityReadiness.class);
		doAnswer(invocation -> { calls.incrementAndGet(); entered.countDown(); assertThat(release.await(5, TimeUnit.SECONDS)).isTrue(); return null; }).when(readiness).requireReady();
		try (var indicator = new IdentityReadinessHealthIndicator(() -> readiness, Duration.ofSeconds(2), Duration.ofMillis(50));
				var executor = Executors.newFixedThreadPool(2)) {
			var first = executor.submit(() -> { return indicator.health(); });
			try {
				assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
				for (int i = 0; i < 20; i++) { assertThat(executor.submit(() -> { return indicator.health(); }).get(200, TimeUnit.MILLISECONDS).getStatus()).isEqualTo(Status.DOWN); }
				assertThat(calls.get()).isEqualTo(1);
			}
			finally { release.countDown(); }
			assertThat(first.get(1, TimeUnit.SECONDS).getStatus()).isEqualTo(Status.UP);
		}
	}

	@Test
	void timeoutKeepsUninterruptibleWorkBoundedAndRecoversAfterItActuallyFinishes(CapturedOutput output) throws Exception {
		var entered = new CountDownLatch(1); var release = new CountDownLatch(1); var finished = new CountDownLatch(1); var calls = new AtomicInteger();
		var readiness = mock(IdentityReadiness.class);
		doAnswer(invocation -> {
			if (calls.incrementAndGet() == 1) {
				entered.countDown();
				while (release.getCount() != 0) { try { release.await(); } catch (InterruptedException ignored) { } }
				finished.countDown();
			}
			return null;
		}).when(readiness).requireReady();
		try (var indicator = new IdentityReadinessHealthIndicator(() -> readiness, Duration.ofMillis(50), Duration.ZERO);
				var executor = Executors.newSingleThreadExecutor()) {
			try {
				var first = executor.submit(() -> { return indicator.health(); });
				assertThat(entered.await(1, TimeUnit.SECONDS)).isTrue();
				assertThat(first.get(500, TimeUnit.MILLISECONDS).getStatus()).isEqualTo(Status.DOWN);
				for (int i = 0; i < 20; i++) { assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN); }
				assertThat(calls.get()).isEqualTo(1);
			}
			finally { release.countDown(); }
			assertThat(finished.await(1, TimeUnit.SECONDS)).isTrue();
			org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(2)).untilAsserted(() -> assertThat(indicator.health().getStatus()).isEqualTo(Status.UP));
			assertThat(output.getAll()).containsOnlyOnce("Readiness unavailable: TIMEOUT").containsOnlyOnce("Readiness recovered");
		}
	}

	@Test
	void completedChecksCoalesceBrieflyAndFailuresExpireSoRepairCanRecoverReadiness(CapturedOutput output) {
		var calls = new AtomicInteger(); var readiness = mock(IdentityReadiness.class);
		doAnswer(invocation -> { if (calls.incrementAndGet() <= 2) { throw new IllegalStateException("private dependency detail"); } return null; }).when(readiness).requireReady();
		try (var indicator = new IdentityReadinessHealthIndicator(() -> readiness, Duration.ofSeconds(1), Duration.ofMillis(100))) {
			assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN);
			assertThat(indicator.health().getDetails()).isEmpty();
			for (int i = 0; i < 20; i++) { assertThat(indicator.health().getStatus()).isEqualTo(Status.DOWN); }
			assertThat(calls.get()).isEqualTo(1);
			org.awaitility.Awaitility.await().atMost(Duration.ofSeconds(2)).untilAsserted(() -> assertThat(indicator.health().getStatus()).isEqualTo(Status.UP));
			assertThat(indicator.health().getDetails()).isEmpty();
			assertThat(calls.get()).isEqualTo(3);
			assertThat(output.getAll()).containsOnlyOnce("Readiness unavailable: UNKNOWN").containsOnlyOnce("Readiness recovered")
					.doesNotContain("private dependency detail");
		}
	}
}
