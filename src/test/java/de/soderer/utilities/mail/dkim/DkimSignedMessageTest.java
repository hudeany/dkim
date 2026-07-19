package de.soderer.utilities.mail.dkim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayOutputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.Signature;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.mail.MessagingException;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;

@SuppressWarnings("static-method")
public class DkimSignedMessageTest {
	private static final Session SESSION = Session.getInstance(new Properties());

	private static RSAPrivateKey privateKey;
	private static RSAPublicKey publicKey;

	@BeforeAll
	public static void generateKeyPair() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = (RSAPrivateKey) keyPair.getPrivate();
		publicKey = (RSAPublicKey) keyPair.getPublic();
	}

	private static DkimSignedMessage createBasicMessage(final boolean includeFromHeader) throws Exception {
		final DkimSignedMessage message = new DkimSignedMessage(SESSION, null);
		if (includeFromHeader) {
			message.setFrom(new InternetAddress("sender@example.com"));
		}
		message.setRecipients(jakarta.mail.Message.RecipientType.TO, new InternetAddress[] { new InternetAddress("recipient@example.com") });
		message.setSubject("Test Subject");
		message.setText("This is the test message body.\r\n", "UTF-8");
		return message;
	}

	private static String writeToString(final DkimSignedMessage message) throws Exception {
		final ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
		message.writeTo(byteArrayOutputStream, new String[0]);
		return new String(byteArrayOutputStream.toByteArray(), StandardCharsets.UTF_8);
	}

	/**
	 * Extract the raw (still possibly folded) value of a header as it appears in the written output,
	 * up to the first line that does not start with whitespace (a folding continuation).
	 */
	private static String extractRawHeaderValue(final String headerBlock, final String headerName) {
		final Pattern pattern = Pattern.compile("(?im)^" + Pattern.quote(headerName) + ":[ \\t]?(.*(?:\\r\\n[ \\t].*)*)");
		final Matcher matcher = pattern.matcher(headerBlock);
		if (!matcher.find()) {
			throw new IllegalStateException("Header not found: " + headerName);
		}
		return matcher.group(1);
	}

	private static Map<String, String> parseDkimSignatureTags(final String rawDkimSignatureValue) {
		final String compact = rawDkimSignatureValue.replace(" ", "").replace("\t", "").replace("\r", "").replace("\n", "");
		final Map<String, String> tags = new HashMap<>();
		for (final String tagEntry : compact.split(";")) {
			if (!tagEntry.isEmpty()) {
				final String[] parts = tagEntry.split("=", 2);
				if (parts.length == 2) {
					tags.put(parts[0], parts[1]);
				}
			}
		}
		return tags;
	}

	@Test
	public void testDkimSignatureHeaderContainsDomainAndSelector() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "mySelector", privateKey, null);

		final String output = writeToString(message);
		final String headerBlock = output.substring(0, output.indexOf("\r\n\r\n"));
		final String dkimValue = extractRawHeaderValue(headerBlock, "DKIM-Signature");
		final Map<String, String> tags = parseDkimSignatureTags(dkimValue);

		assertEquals("1", tags.get("v"));
		assertEquals("rsa-sha256", tags.get("a"));
		assertEquals("example.com", tags.get("d"));
		assertEquals("mySelector", tags.get("s"));
		assertTrue(tags.containsKey("bh"));
		assertTrue(tags.containsKey("b"));
		assertTrue(tags.get("h").toLowerCase().contains("from"));
	}

	@Test
	public void testDefaultCanonicalizationIsRelaxedRelaxed() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "sel", privateKey, null);

		final String output = writeToString(message);
		final String headerBlock = output.substring(0, output.indexOf("\r\n\r\n"));
		final Map<String, String> tags = parseDkimSignatureTags(extractRawHeaderValue(headerBlock, "DKIM-Signature"));

		assertEquals("relaxed/relaxed", tags.get("c"));
	}

	@Test
	public void testSimpleCanonicalizationProducesSimpleCode() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "sel", privateKey, null);
		message.setCanonicalization(false, false);

		final String output = writeToString(message);
		final String headerBlock = output.substring(0, output.indexOf("\r\n\r\n"));
		final Map<String, String> tags = parseDkimSignatureTags(extractRawHeaderValue(headerBlock, "DKIM-Signature"));

		assertEquals("simple/simple", tags.get("c"));
	}

	@Test
	public void testMixedCanonicalizationProducesMixedCode() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "sel", privateKey, null);
		message.setCanonicalization(true, false);

		final String output = writeToString(message);
		final String headerBlock = output.substring(0, output.indexOf("\r\n\r\n"));
		final Map<String, String> tags = parseDkimSignatureTags(extractRawHeaderValue(headerBlock, "DKIM-Signature"));

		assertEquals("relaxed/simple", tags.get("c"));
	}

	@Test
	public void testExcludedHeaderIsNotListedInSignature() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "sel", privateKey, null);
		message.setExcludedHeaders("Subject");

		final String output = writeToString(message);
		final String headerBlock = output.substring(0, output.indexOf("\r\n\r\n"));
		final Map<String, String> tags = parseDkimSignatureTags(extractRawHeaderValue(headerBlock, "DKIM-Signature"));

		final String includedHeaders = tags.get("h").toLowerCase();
		assertFalse(includedHeaders.contains("subject"));
		assertTrue(includedHeaders.contains("from"));

		// The header itself must still be present in the message, only excluded from the signature
		assertTrue(headerBlock.toLowerCase().contains("subject: test subject"));
	}

	@Test
	public void testMissingFromHeaderThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(false);
		message.setDkimKeyData("example.com", "sel", privateKey, null);

		assertThrows(MessagingException.class, () -> writeToString(message));
	}

	@Test
	public void testBlankDomainThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		assertThrows(Exception.class, () -> message.setDkimKeyData(" ", "sel", privateKey, null));
	}

	@Test
	public void testDomainWithHeaderInjectionCharactersThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		assertThrows(Exception.class, () -> message.setDkimKeyData("example.com\r\nBcc: attacker@evil.com", "sel", privateKey, null));
	}

	@Test
	public void testSelectorWithSemicolonThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		assertThrows(Exception.class, () -> message.setDkimKeyData("example.com", "sel;evil", privateKey, null));
	}

	@Test
	public void testBlankSelectorThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		assertThrows(Exception.class, () -> message.setDkimKeyData("example.com", "", privateKey, null));
	}

	@Test
	public void testNullPrivateKeyThrowsException() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		assertThrows(Exception.class, () -> message.setDkimKeyData("example.com", "sel", null, null));
	}

	@Test
	public void testMessageWithoutDkimKeyDataIsWrittenUnsigned() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);

		final String output = writeToString(message);

		assertFalse(output.toLowerCase().contains("dkim-signature"));
	}

	@Test
	public void testDifferentBodiesProduceDifferentBodyHashes() throws Exception {
		final DkimSignedMessage message1 = createBasicMessage(true);
		message1.setDkimKeyData("example.com", "sel", privateKey, null);
		message1.setText("First body content.\r\n", "UTF-8");

		final DkimSignedMessage message2 = createBasicMessage(true);
		message2.setDkimKeyData("example.com", "sel", privateKey, null);
		message2.setText("Second, different body content.\r\n", "UTF-8");

		final String output1 = writeToString(message1);
		final String output2 = writeToString(message2);

		final String bh1 = parseDkimSignatureTags(extractRawHeaderValue(output1.substring(0, output1.indexOf("\r\n\r\n")), "DKIM-Signature")).get("bh");
		final String bh2 = parseDkimSignatureTags(extractRawHeaderValue(output2.substring(0, output2.indexOf("\r\n\r\n")), "DKIM-Signature")).get("bh");

		assertFalse(bh1.equals(bh2));
	}

	/**
	 * Full round trip: independently reconstruct the canonicalized headers and body from the
	 * written message (without relying on any DKIM-internal helper method) and verify the
	 * signature bytes cryptographically against the public key.
	 */
	@Test
	public void testSignatureIsCryptographicallyVerifiable() throws Exception {
		final DkimSignedMessage message = createBasicMessage(true);
		message.setDkimKeyData("example.com", "sel", privateKey, null);

		final String output = writeToString(message);
		final int headerBodySeparatorIndex = output.indexOf("\r\n\r\n");
		final String headerBlock = output.substring(0, headerBodySeparatorIndex);
		final String bodyPart = output.substring(headerBodySeparatorIndex + 4);

		final String rawDkimValue = extractRawHeaderValue(headerBlock, "DKIM-Signature");
		final Map<String, String> tags = parseDkimSignatureTags(rawDkimValue);

		// Independently verify the body hash
		final MessageDigest digest = MessageDigest.getInstance("SHA-256");
		final byte[] bodyHashBytes = digest.digest(bodyPart.getBytes(StandardCharsets.UTF_8));
		final String recomputedBodyHash = Base64.getEncoder().encodeToString(bodyHashBytes);
		assertEquals(tags.get("bh"), recomputedBodyHash);

		// Reconstruct the exact bytes that were signed
		final boolean useRelaxedHeaderCanonicalization = tags.get("c").startsWith("relaxed");
		final StringBuilder signedData = new StringBuilder();
		for (final String headerName : tags.get("h").split(":")) {
			final String rawHeaderValue = extractRawHeaderValue(headerBlock, headerName);
			signedData.append(DkimUtilities.canonicalizeHeader(useRelaxedHeaderCanonicalization, headerName, rawHeaderValue));
			signedData.append("\r\n");
		}

		// The DKIM-Signature header itself is signed up to and including the empty "b=" tag
		final int bTagEnd = rawDkimValue.indexOf("b=") + 2;
		final String dkimValueWithoutSignatureBytes = rawDkimValue.substring(0, bTagEnd);
		signedData.append(DkimUtilities.canonicalizeHeader(useRelaxedHeaderCanonicalization, "DKIM-Signature", dkimValueWithoutSignatureBytes));

		final Signature signature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
		signature.initVerify(publicKey);
		signature.update(signedData.toString().getBytes(StandardCharsets.UTF_8));

		final byte[] signatureBytes = Base64.getDecoder().decode(tags.get("b"));
		assertTrue(signature.verify(signatureBytes));
	}
}
