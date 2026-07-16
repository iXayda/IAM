package com.ixayda.iam.authorization.internal;

import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.security.spec.RSAPublicKeySpec;
import java.time.Instant;
import java.util.Arrays;
import java.util.Objects;
import java.util.UUID;
import java.util.function.Supplier;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.KeyUse;
import com.nimbusds.jose.jwk.RSAKey;
import org.springframework.dao.DataRetrievalFailureException;

final class AuthorizationSigningKeyCodec {

	private static final int RSA_KEY_SIZE_BITS = 3072;

	private static final int RSA_MODULUS_BYTES = RSA_KEY_SIZE_BITS / Byte.SIZE;

	private static final BigInteger RSA_PUBLIC_EXPONENT = RSAKeyGenParameterSpec.F4;

	private static final byte[] SELF_TEST_MESSAGE =
			"iam-authorization-signing-key-self-test-v1".getBytes(java.nio.charset.StandardCharsets.US_ASCII);

	private final AuthorizationSigningKeyCipher cipher;

	private final AuthorizationSigningKeyAttestation attestation;

	private final SecureRandom random;

	private final Supplier<UUID> identifierSource;

	AuthorizationSigningKeyCodec(AuthorizationSigningKeyCipher cipher,
			AuthorizationSigningKeyAttestation attestation) {
		this(cipher, attestation, new SecureRandom(), UUID::randomUUID);
	}

	AuthorizationSigningKeyCodec(AuthorizationSigningKeyCipher cipher,
			AuthorizationSigningKeyAttestation attestation, SecureRandom random, Supplier<UUID> identifierSource) {
		this.cipher = Objects.requireNonNull(cipher, "Signing-key cipher must not be null");
		this.attestation = Objects.requireNonNull(attestation, "Signing-key attestation must not be null");
		this.random = Objects.requireNonNull(random, "Secure random generator must not be null");
		this.identifierSource = Objects.requireNonNull(identifierSource, "Signing key ID source must not be null");
	}

	StoredAuthorizationSigningKey generateActive(Instant now) {
		Objects.requireNonNull(now, "Signing key creation time must not be null");
		try {
			KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
			generator.initialize(new RSAKeyGenParameterSpec(RSA_KEY_SIZE_BITS, RSA_PUBLIC_EXPONENT), this.random);
			KeyPair keyPair = generator.generateKeyPair();
			RSAPublicKey publicKey = requirePublicKey(keyPair.getPublic());
			RSAPrivateKey privateKey = requirePrivateKey(keyPair.getPrivate());
			validateKeyPair(publicKey, privateKey);
			selfTest(publicKey, privateKey);

			UUID signingKeyId = Objects.requireNonNull(this.identifierSource.get(), "Generated signing key ID is null");
			byte[] modulus = unsignedFixedLength(publicKey.getModulus());
			String kid = thumbprint(publicKey);
			AuthorizationSigningKeyCipher.KeyContext context =
					new AuthorizationSigningKeyCipher.KeyContext(signingKeyId, kid, modulus,
							publicKey.getPublicExponent().intValueExact());
			byte[] encodedPrivateKey = privateKey.getEncoded();
			try {
				AuthorizationSigningKeyCipher.ProtectedPrivateKey protectedPrivateKey =
						this.cipher.protect(encodedPrivateKey, context);
				StoredAuthorizationSigningKey candidate = new StoredAuthorizationSigningKey(signingKeyId, kid, modulus,
						publicKey.getPublicExponent().intValueExact(), StoredAuthorizationSigningKey.Status.ACTIVE,
						null, protectedPrivateKey, now, now, now, now, null, null, null, 0, now);
				return candidate.withAttestation(this.attestation.attest(candidate));
			}
			finally {
				Arrays.fill(encodedPrivateKey, (byte) 0);
			}
		}
		catch (GeneralSecurityException | JOSEException exception) {
			throw new IllegalStateException("Authorization signing key generation failed", exception);
		}
	}

	RSAKey restoreActive(StoredAuthorizationSigningKey stored) {
		Objects.requireNonNull(stored, "Stored signing key must not be null");
		this.attestation.verify(stored);
		if (stored.status() != StoredAuthorizationSigningKey.Status.ACTIVE || stored.privateKey() == null) {
			throw new DataRetrievalFailureException("The active authorization signing key has no private material");
		}
		RSAPublicKey publicKey = restorePublicKey(stored);
		AuthorizationSigningKeyCipher.KeyContext context = context(stored);
		byte[] encodedPrivateKey = this.cipher.reveal(stored.privateKey(), context);
		try {
			PrivateKey decoded = KeyFactory.getInstance("RSA")
				.generatePrivate(new PKCS8EncodedKeySpec(encodedPrivateKey));
			RSAPrivateKey privateKey = requirePrivateKey(decoded);
			validateKeyPair(publicKey, privateKey);
			selfTest(publicKey, privateKey);
			return jwk(publicKey, privateKey, stored.kid());
		}
		catch (GeneralSecurityException exception) {
			throw new DataRetrievalFailureException("Authorization signing private key is invalid", exception);
		}
		finally {
			Arrays.fill(encodedPrivateKey, (byte) 0);
		}
	}

	RSAKey restorePublic(StoredAuthorizationSigningKey stored) {
		Objects.requireNonNull(stored, "Stored signing key must not be null");
		this.attestation.verify(stored);
		RSAPublicKey publicKey = restorePublicKey(stored);
		return jwk(publicKey, null, stored.kid());
	}

	private RSAPublicKey restorePublicKey(StoredAuthorizationSigningKey stored) {
		try {
			RSAPublicKey publicKey = (RSAPublicKey) KeyFactory.getInstance("RSA")
				.generatePublic(new RSAPublicKeySpec(new BigInteger(1, stored.publicModulus()),
						BigInteger.valueOf(stored.publicExponent())));
			validatePublicKey(publicKey);
			if (!stored.kid().equals(thumbprint(publicKey))) {
				throw new DataRetrievalFailureException("Authorization signing key thumbprint validation failed");
			}
			return publicKey;
		}
		catch (DataRetrievalFailureException exception) {
			throw exception;
		}
		catch (GeneralSecurityException | JOSEException exception) {
			throw new DataRetrievalFailureException("Authorization signing public key is invalid", exception);
		}
	}

	private static AuthorizationSigningKeyCipher.KeyContext context(StoredAuthorizationSigningKey stored) {
		return new AuthorizationSigningKeyCipher.KeyContext(stored.signingKeyId(), stored.kid(),
				stored.publicModulus(), stored.publicExponent());
	}

	private static RSAKey jwk(RSAPublicKey publicKey, RSAPrivateKey privateKey, String kid) {
		RSAKey.Builder builder = new RSAKey.Builder(publicKey).keyUse(KeyUse.SIGNATURE)
			.algorithm(JWSAlgorithm.RS256)
			.keyID(kid);
		if (privateKey != null) {
			builder.privateKey(privateKey);
		}
		return builder.build();
	}

	private static String thumbprint(RSAPublicKey publicKey) throws JOSEException {
		return new RSAKey.Builder(publicKey).build().computeThumbprint().toString();
	}

	private static RSAPublicKey requirePublicKey(java.security.PublicKey key) {
		if (key instanceof RSAPublicKey rsaKey) {
			return rsaKey;
		}
		throw new IllegalStateException("Generated key is not an RSA public key");
	}

	private static RSAPrivateKey requirePrivateKey(PrivateKey key) {
		if (key instanceof RSAPrivateKey rsaKey) {
			return rsaKey;
		}
		throw new DataRetrievalFailureException("Key is not an RSA private key");
	}

	private static void validateKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
		validatePublicKey(publicKey);
		if (!publicKey.getModulus().equals(privateKey.getModulus())) {
			throw new DataRetrievalFailureException("Authorization signing public and private keys do not match");
		}
	}

	private static void validatePublicKey(RSAPublicKey publicKey) {
		if (publicKey.getModulus().bitLength() != RSA_KEY_SIZE_BITS
				|| !RSA_PUBLIC_EXPONENT.equals(publicKey.getPublicExponent())) {
			throw new DataRetrievalFailureException("Authorization signing key must be RSA-3072 with exponent 65537");
		}
	}

	private static void selfTest(RSAPublicKey publicKey, RSAPrivateKey privateKey) throws GeneralSecurityException {
		Signature signer = Signature.getInstance("SHA256withRSA");
		signer.initSign(privateKey);
		signer.update(SELF_TEST_MESSAGE);
		byte[] signature = signer.sign();
		try {
			Signature verifier = Signature.getInstance("SHA256withRSA");
			verifier.initVerify(publicKey);
			verifier.update(SELF_TEST_MESSAGE);
			if (!verifier.verify(signature)) {
				throw new GeneralSecurityException("Authorization signing key self-test failed");
			}
		}
		finally {
			Arrays.fill(signature, (byte) 0);
		}
	}

	private static byte[] unsignedFixedLength(BigInteger value) {
		byte[] encoded = value.toByteArray();
		if (encoded.length == RSA_MODULUS_BYTES) {
			return encoded;
		}
		if (encoded.length == RSA_MODULUS_BYTES + 1 && encoded[0] == 0) {
			return Arrays.copyOfRange(encoded, 1, encoded.length);
		}
		throw new IllegalStateException("Generated RSA modulus is not 3072 bits");
	}

}
