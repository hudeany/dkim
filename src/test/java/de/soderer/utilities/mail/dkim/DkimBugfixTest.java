package de.soderer.utilities.mail.dkim;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPrivateKey;
import java.util.Collections;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Properties;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import jakarta.mail.Message;
import jakarta.mail.Session;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeBodyPart;
import jakarta.mail.internet.MimeMessage;
import jakarta.mail.internet.MimeMultipart;

/**
 * Regression tests for bugs found in the review of the DKIM library.
 * The messages in "dkim/dkimpy_*.eml" were signed with dkimpy, an independent DKIM implementation, using the key in "dkim/test_public_key.txt".
 */
@SuppressWarnings("static-method")
public class DkimBugfixTest {
	private static final Session SESSION = Session.getInstance(new Properties());

	private static RSAPrivateKey privateKey;

	@BeforeAll
	public static void setUp() throws Exception {
		final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(2048);
		final KeyPair keyPair = keyPairGenerator.generateKeyPair();
		privateKey = (RSAPrivateKey) keyPair.getPrivate();
		DkimUtilities.cacheDomainKey("own.example.com", "sel", createDomainKey(Base64.getEncoder().encodeToString(keyPair.getPublic().getEncoded())));

		try (InputStream inputStream = DkimBugfixTest.class.getClassLoader().getResourceAsStream("dkim/test_public_key.txt")) {
			final String dkimpyPublicKey = new String(inputStream.readAllBytes(), StandardCharsets.US_ASCII).trim();
			DkimUtilities.cacheDomainKey("example.com", "sel", createDomainKey(dkimpyPublicKey));
			DkimUtilities.cacheDomainKey("other.example.net", "sel", createDomainKey(dkimpyPublicKey));
		}
	}

	private static DomainKey createDomainKey(final String publicKeyBase64) throws Exception {
		final Map<Character, String> tags = new HashMap<>();
		tags.put('v', "DKIM1");
		tags.put('k', "rsa");
		tags.put('p', publicKeyBase64);
		return new DomainKey(tags);
	}

	private static DkimSignedMessage createMessage(final String messageId) throws Exception {
		final DkimSignedMessage message = new DkimSignedMessage(SESSION, messageId);
		message.setFrom(new InternetAddress("sender@own.example.com"));
		message.setRecipients(Message.RecipientType.TO, new InternetAddress[] { new InternetAddress("recipient@example.com") });
		message.setSubject("Test Subject");
		message.setText("This is the test message body.\r\nSecond line  with   spaces  \r\n", "UTF-8");
		return message;
	}

	private static byte[] write(final DkimSignedMessage message, final String... ignoreList) throws Exception {
		final ByteArrayOutputStream outputStream = new ByteArrayOutputStream();
		message.writeTo(outputStream, ignoreList);
		return outputStream.toByteArray();
	}

	/**
	 * Parses written message data like a receiving mail server would, adding a Return-Path of the signing domain
	 */
	private static MimeMessage receive(final byte[] messageData) throws Exception {
		final MimeMessage receivedMessage = new MimeMessage(SESSION, new ByteArrayInputStream(messageData));
		if (receivedMessage.getHeader("Return-Path") == null) {
			receivedMessage.setHeader("Return-Path", "<bounce@own.example.com>");
		}
		return receivedMessage;
	}

	private static MimeMessage readResource(final String name) throws Exception {
		try (InputStream inputStream = DkimBugfixTest.class.getClassLoader().getResourceAsStream("dkim/" + name)) {
			return new MimeMessage(SESSION, inputStream);
		}
	}

	@Test
	public void testVerifyMessagesSignedByDkimpy() throws Exception {
		for (final String name : new String[] { "dkimpy_relaxed.eml", "dkimpy_simple.eml", "dkimpy_quoted_printable.eml", "dkimpy_duplicate_header.eml", "dkimpy_identity.eml" }) {
			assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(readResource(name)), name);
		}
	}

	@Test
	public void testTamperedMessageIsRejected() throws Exception {
		final MimeMessage message = readResource("dkimpy_relaxed.eml");
		message.setHeader("Subject", "Changed subject");
		assertFalse(DkimUtilities.checkDkimSignature(message));
	}

	@Test
	public void testRoundTripSimpleAndRelaxed() throws Exception {
		for (final boolean relaxedHeader : new boolean[] { false, true }) {
			for (final boolean relaxedBody : new boolean[] { false, true }) {
				final DkimSignedMessage message = createMessage("<1@own.example.com>");
				message.setDkimKeyData("own.example.com", "sel", privateKey, null);
				message.setCanonicalization(relaxedHeader, relaxedBody);
				assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(write(message))));
			}
		}
	}

	@Test
	public void testIgnoredHeadersAreNotSigned() throws Exception {
		final DkimSignedMessage message = createMessage("<2@own.example.com>");
		message.setRecipients(Message.RecipientType.BCC, new InternetAddress[] { new InternetAddress("hidden@example.com") });
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		final byte[] messageData = write(message, "Bcc", "Content-Length");
		assertFalse(new String(messageData, StandardCharsets.UTF_8).contains("Bcc"));
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(messageData)));
	}

	@Test
	public void testDuplicateHeaders() throws Exception {
		final DkimSignedMessage message = createMessage("<3@own.example.com>");
		message.addHeader("X-Dup", "first");
		message.addHeader("X-Dup", "second");
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(write(message))));
	}

	@Test
	public void testIdentityIsDkimQuotedPrintable() throws Exception {
		final DkimSignedMessage message = createMessage("<4@own.example.com>");
		message.setDkimKeyData("own.example.com", "sel", privateKey, "a.very.long.identity.name@mail.own.example.com");
		final byte[] messageData = write(message);
		assertTrue(new String(messageData, StandardCharsets.UTF_8).contains("i=a.very.long.identity.name@mail.own.example.com;"));
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(messageData)));

		assertEquals("a=3Db=3Bc=C3=A4@x", DkimUtilities.encodeDkimQuotedPrintable("a=b;c\u00e4@x"));
		assertEquals("a=b;c\u00e4@x", DkimUtilities.decodeDkimQuotedPrintable("a=3Db=3Bc=C3=A4@x"));
		assertThrows(Exception.class, () -> createMessage(null).setDkimKeyData("own.example.com", "sel", privateKey, "user@other.com"));
	}

	@Test
	public void testMessageIdIsGeneratedWithoutGivenId() throws Exception {
		final DkimSignedMessage message = createMessage(null);
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		final MimeMessage receivedMessage = receive(write(message));
		assertTrue(receivedMessage.getHeader("Message-ID") != null);
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receivedMessage));
	}

	@Test
	public void testExcludedHeadersAreCaseInsensitive() throws Exception {
		final DkimSignedMessage message = createMessage("<5@own.example.com>");
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		message.setExcludedHeaders("subject");
		final MimeMessage receivedMessage = receive(write(message));
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receivedMessage));
		// The subject is not signed, so changing it keeps the signature valid
		receivedMessage.setHeader("Subject", "Changed subject");
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receivedMessage));
	}

	@Test
	public void testEightBitBodyIsKeptUnchanged() throws Exception {
		final DkimSignedMessage message = createMessage("<6@own.example.com>");
		message.setText("Gr\u00fc\u00dfe aus M\u00fcnchen\r\n", "ISO-8859-1");
		message.setHeader("Content-Transfer-Encoding", "8bit");
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		final byte[] messageData = write(message);
		assertTrue(new String(messageData, StandardCharsets.ISO_8859_1).contains("Gr\u00fc\u00dfe aus M\u00fcnchen"));
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(messageData)));
	}

	@Test
	public void testMultipartMessage() throws Exception {
		final DkimSignedMessage message = createMessage("<7@own.example.com>");
		final MimeMultipart multipart = new MimeMultipart();
		final MimeBodyPart textPart = new MimeBodyPart();
		textPart.setText("Text part \u00e4\u00f6\u00fc\r\n", "UTF-8");
		multipart.addBodyPart(textPart);
		final MimeBodyPart attachmentPart = new MimeBodyPart();
		attachmentPart.setContent(new byte[] { 1, 2, 3, (byte) 200 }, "application/octet-stream");
		attachmentPart.setFileName("a.bin");
		multipart.addBodyPart(attachmentPart);
		message.setContent(multipart);
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		message.setCanonicalization(false, false);
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receive(write(message))));
	}

	@Test
	public void testRelaxedHeaderCanonicalizationIsLocaleIndependent() {
		final Locale defaultLocale = Locale.getDefault();
		try {
			Locale.setDefault(new Locale("tr", "TR"));
			assertEquals("mime-version:1.0", DkimUtilities.canonicalizeHeader(true, "MIME-Version", " 1.0"));
		} finally {
			Locale.setDefault(defaultLocale);
		}
	}

	@Test
	public void testSignatureValueRemovalKeepsOtherTags() {
		assertEquals("DKIM-Signature: v=1; b=; bh=abc; d=example.com", DkimUtilities.removeSignatureValue("DKIM-Signature: v=1; b=SIGNATURE\r\n MORE; bh=abc; d=example.com"));
		assertEquals("DKIM-Signature: v=1; bh=abc; b=", DkimUtilities.removeSignatureValue("DKIM-Signature: v=1; bh=abc; b=SIGNATURE"));
	}

	@Test
	public void testDomainKeyRecordParsing() throws Exception {
		final Map<Character, String> tags = DkimUtilities.parseDomainKeyTags("v=DKIM1; k=rsa; unknown=value; ; p=ABC ;");
		assertEquals("DKIM1", tags.get('v'));
		assertEquals("ABC", tags.get('p'));
		assertNull(tags.get('u'));
	}

	@Test
	public void testRevokedAndIncompatibleDomainKeys() {
		final Map<Character, String> revokedTags = new HashMap<>();
		revokedTags.put('p', "");
		final Exception revokedException = assertThrows(Exception.class, () -> new DomainKey(revokedTags));
		assertTrue(revokedException.getMessage().contains("revoked"));

		final Map<Character, String> sha1Tags = new HashMap<>();
		sha1Tags.put('h', "sha1");
		sha1Tags.put('p', "AAAA");
		assertThrows(Exception.class, () -> new DomainKey(sha1Tags));
	}

	@Test
	public void testInvalidSignatureNextToValidSignature() throws Exception {
		final DkimVerificationResult result = DkimUtilities.verifyDkimSignatures(readResource("dkimpy_multiple_one_invalid.eml"), DkimUtilities.DomainAlignment.RETURN_PATH);
		assertEquals(2, result.getSignatureResults().size());
		assertFalse(result.getSignatureResults().get(0).isValid());
		assertTrue(result.getSignatureResults().get(1).isValid());
		assertTrue(result.isValid());
		assertEquals(Arrays.asList("example.com"), result.getValidDomains());
		assertEquals(Boolean.TRUE, DkimUtilities.checkDkimSignature(readResource("dkimpy_multiple_one_invalid.eml")));
	}

	@Test
	public void testDomainAlignment() throws Exception {
		// Valid signature of another domain than the From and Return-Path domain
		final MimeMessage otherDomainMessage = readResource("dkimpy_other_domain.eml");
		final DkimVerificationResult returnPathResult = DkimUtilities.verifyDkimSignatures(otherDomainMessage, DkimUtilities.DomainAlignment.RETURN_PATH);
		assertTrue(returnPathResult.getSignatureResults().get(0).isValid());
		assertFalse(returnPathResult.isValid());
		assertEquals(Collections.emptyList(), returnPathResult.getValidDomains());
		assertEquals(Boolean.FALSE, DkimUtilities.checkDkimSignature(otherDomainMessage));
		assertTrue(DkimUtilities.verifyDkimSignatures(otherDomainMessage, DkimUtilities.DomainAlignment.NONE).isValid());
		assertEquals(Arrays.asList("other.example.net"), DkimUtilities.verifyDkimSignatures(otherDomainMessage, DkimUtilities.DomainAlignment.NONE).getValidDomains());

		// Signed by the From domain, Return-Path of a mailing service
		final MimeMessage fromAlignedMessage = readResource("dkimpy_from_aligned.eml");
		assertTrue(DkimUtilities.verifyDkimSignatures(fromAlignedMessage, DkimUtilities.DomainAlignment.FROM).isValid());
		assertFalse(DkimUtilities.verifyDkimSignatures(fromAlignedMessage, DkimUtilities.DomainAlignment.RETURN_PATH).isValid());
		// The From domain is the default
		assertEquals(Boolean.TRUE, DkimUtilities.checkDkimSignature(fromAlignedMessage));

		// Return-Path in a subdomain of the signing domain
		assertTrue(DkimUtilities.verifyDkimSignatures(readResource("dkimpy_return_path_subdomain.eml"), DkimUtilities.DomainAlignment.RETURN_PATH).isValid());
	}

	@Test
	public void testDefaultAlignmentDoesNotNeedReturnPath() throws Exception {
		final DkimSignedMessage message = createMessage("<9@own.example.com>");
		message.setDkimKeyData("own.example.com", "sel", privateKey, null);
		final MimeMessage receivedMessage = new MimeMessage(SESSION, new ByteArrayInputStream(write(message)));
		assertEquals(Boolean.TRUE, DkimUtilities.verifyDkimSignature(receivedMessage));
		assertFalse(DkimUtilities.verifyDkimSignatures(receivedMessage, DkimUtilities.DomainAlignment.RETURN_PATH).isValid());
	}

	@Test
	public void testMaximumNumberOfVerifiedSignatures() throws Exception {
		final DkimVerificationResult result = DkimUtilities.verifyDkimSignatures(readResource("dkimpy_too_many_signatures.eml"), DkimUtilities.DomainAlignment.RETURN_PATH);
		assertEquals(DkimUtilities.MAXIMUM_SIGNATURES_TO_VERIFY + 1, result.getSignatureResults().size());
		assertFalse(result.isValid());
		assertTrue(result.getSignatureResults().get(DkimUtilities.MAXIMUM_SIGNATURES_TO_VERIFY).getErrorMessage().contains("maximum number"));
	}

	@Test
	public void testUnsignedMessage() throws Exception {
		final DkimSignedMessage message = createMessage("<8@own.example.com>");
		final MimeMessage receivedMessage = receive(write(message));
		assertNull(DkimUtilities.checkDkimSignature(receivedMessage));
		assertFalse(DkimUtilities.verifyDkimSignatures(receivedMessage, DkimUtilities.DomainAlignment.NONE).isSigned());
	}
}
