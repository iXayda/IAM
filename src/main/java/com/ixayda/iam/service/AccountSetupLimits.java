package com.ixayda.iam.service;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Arrays;
import java.util.HexFormat;

import com.ixayda.iam.model.AccountSetupContext;
import com.ixayda.iam.repository.AccountSetupLimitRepository;

import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Propagation;
import org.springframework.transaction.annotation.Transactional;

/** Independent proof-entry budgets. Lock source, then account, before the user row. */
@Service
@Transactional(propagation = Propagation.MANDATORY)
public class AccountSetupLimits {

	private final AccountSetupLimitRepository repository;

	AccountSetupLimits(AccountSetupLimitRepository repository) { this.repository = repository; }

	Attempt lock(String account, AccountSetupContext context) {
		byte[] address = context.clientAddress().getAddress();
		if (address.length == 16 && Arrays.equals(Arrays.copyOf(address, 12),
				new byte[] { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, (byte) 0xff, (byte) 0xff })) {
			address = Arrays.copyOfRange(address, 12, 16);
		}
		String sourceKey = digest("iam:account-setup:source:", address);
		String accountKey = digest("iam:account-setup:account:", account.getBytes(StandardCharsets.US_ASCII));
		boolean allowed = this.repository.lockLimit("source", sourceKey) < 30
				&& this.repository.lockLimit("account", accountKey) < 5;
		return new Attempt(sourceKey, accountKey, allowed);
	}

	void failed(Attempt attempt) {
		this.repository.recordFailure("source", attempt.sourceKey());
		this.repository.recordFailure("account", attempt.accountKey());
	}

	void succeeded(Attempt attempt) { this.repository.clearAccount(attempt.accountKey()); }

	void cleanUpExpired() { this.repository.cleanUpExpired(); }

	record Attempt(String sourceKey, String accountKey, boolean allowed) { }

	private static String digest(String purpose, byte[] value) {
		try {
			MessageDigest digest = MessageDigest.getInstance("SHA-256");
			digest.update(purpose.getBytes(StandardCharsets.US_ASCII));
			return HexFormat.of().formatHex(digest.digest(value));
		}
		catch (NoSuchAlgorithmException ex) { throw new IllegalStateException("SHA-256 is unavailable", ex); }
	}

}
