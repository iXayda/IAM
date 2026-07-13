package com.ixayda.iam.auth.internal;

import java.time.Duration;
import java.util.Objects;

import com.ixayda.iam.session.SessionAbsoluteTtl;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.bind.DefaultValue;

@ConfigurationProperties("iam.auth.local")
record LocalPasswordLoginProperties(Duration sessionAbsoluteTtl) {

	LocalPasswordLoginProperties(@DefaultValue("8h") Duration sessionAbsoluteTtl) {
		this.sessionAbsoluteTtl = Objects.requireNonNull(sessionAbsoluteTtl,
				"Local password session absolute TTL must not be null");
		new SessionAbsoluteTtl(sessionAbsoluteTtl);
	}

	SessionAbsoluteTtl absoluteTtl() {
		return new SessionAbsoluteTtl(this.sessionAbsoluteTtl);
	}

}
