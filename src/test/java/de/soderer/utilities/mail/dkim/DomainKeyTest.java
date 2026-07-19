package de.soderer.utilities.mail.dkim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

@SuppressWarnings("static-method")
public class DomainKeyTest {
	private static PrivateKey privateKey;
	private static PublicKey publicKey;
	private static String publicKeyBase64;

	private static PrivateKey otherPrivateKey;

	@BeforeAll
	public static void generateKeyPairs() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);

		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = keyPair.getPrivate();
		publicKey = keyPair.getPublic();
		publicKeyBase64 = Base64.getEncoder().encodeToString(publicKey.getEncoded());

		final KeyPair otherKeyPair = keyPairGenerator.generateKeyPair();
		otherPrivateKey = otherKeyPair.getPrivate();
	}

	private static Map<Character, String> createValidTags() {
		final Map<Character, String> tags = new HashMap<>();
		tags.put('v', "DKIM1");
		tags.put('k', "rsa");
		tags.put('s', "*");
		tags.put('g', "*");
		tags.put('p', publicKeyBase64);
		return tags;
	}

	@Test
	public void testValidDomainKeyIsParsedCorrectly() throws Exception {
		final DomainKey domainKey = new DomainKey(createValidTags());

		assertEquals(publicKey, domainKey.getPublicKey());
		assertTrue(domainKey.getServiceTypes().contains("*"));
		assertTrue(domainKey.getGranularity().matcher("anyLocalPart").matches());
	}

	@Test
	public void testMissingVersionTagDefaultsToCompatibleVersion() throws Exception {
		final Map<Character, String> tags = createValidTags();
		tags.remove('v');

		// No exception expected: absent v-tag falls back to the expected DKIM1 version
		final DomainKey domainKey = new DomainKey(tags);
		assertEquals(publicKey, domainKey.getPublicKey());
	}

	@Test
	public void testWrongVersionThrowsException() {
		final Map<Character, String> tags = createValidTags();
		tags.put('v', "DKIM2");

		final Exception exception = assertThrows(Exception.class, () -> new DomainKey(tags));
		assertTrue(exception.getMessage().contains("Incompatible version"));
	}

	@Test
	public void testWrongKeyTypeThrowsException() {
		final Map<Character, String> tags = createValidTags();
		tags.put('k', "ecdsa");

		final Exception exception = assertThrows(Exception.class, () -> new DomainKey(tags));
		assertTrue(exception.getMessage().contains("Incompatible key type"));
	}

	@Test
	public void testWrongServiceTypeThrowsException() {
		final Map<Character, String> tags = createValidTags();
		tags.put('s', "unknownServiceType");

		final Exception exception = assertThrows(Exception.class, () -> new DomainKey(tags));
		assertTrue(exception.getMessage().contains("Incompatible service type"));
	}

	@Test
	public void testMissingPublicKeyThrowsException() {
		final Map<Character, String> tags = createValidTags();
		tags.remove('p');

		final Exception exception = assertThrows(Exception.class, () -> new DomainKey(tags));
		assertTrue(exception.getMessage().contains("public key"));
	}

	@Test
	public void testInvalidPublicKeyThrowsException() {
		final Map<Character, String> tags = createValidTags();
		tags.put('p', "not-a-valid-base64-encoded-key!!");

		assertThrows(Exception.class, () -> new DomainKey(tags));
	}

	@Test
	public void testCheckSucceedsForMatchingIdentityAndKey() throws Exception {
		final Map<Character, String> tags = createValidTags();
		tags.put('g', "user*");
		final DomainKey domainKey = new DomainKey(tags);

		domainKey.check("user123@example.com", privateKey);
	}

	@Test
	public void testCheckFailsForIdentityNotMatchingGranularity() throws Exception {
		final Map<Character, String> tags = createValidTags();
		tags.put('g', "user*");
		final DomainKey domainKey = new DomainKey(tags);

		final Exception exception = assertThrows(Exception.class, () -> domainKey.check("other123@example.com", privateKey));
		assertTrue(exception.getMessage().contains("Incompatible identity"));
	}

	@Test
	public void testCheckFailsForMismatchedKeyPair() throws Exception {
		final DomainKey domainKey = new DomainKey(createValidTags());

		final Exception exception = assertThrows(Exception.class, () -> domainKey.check("user@example.com", otherPrivateKey));
		assertTrue(exception.getMessage().contains("Incompatible private key and public key"));
	}

	@Test
	public void testGetTagsReturnsOriginalValues() throws Exception {
		final Map<Character, String> tags = createValidTags();
		final DomainKey domainKey = new DomainKey(tags);

		assertEquals("rsa", domainKey.getTags().get('k'));
		assertEquals("*", domainKey.getTags().get('s'));
	}
}
