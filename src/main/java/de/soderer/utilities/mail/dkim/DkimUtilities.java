package de.soderer.utilities.mail.dkim;

import java.io.ByteArrayOutputStream;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.LinkedHashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import de.soderer.utilities.mail.dkim.utilities.IoUtilities;
import de.soderer.utilities.mail.dkim.utilities.MailUtilities;
import de.soderer.utilities.mail.dkim.utilities.Utilities;
import jakarta.mail.Header;
import jakarta.mail.Message;
import jakarta.mail.MessagingException;
import jakarta.mail.internet.InternetAddress;
import jakarta.mail.internet.MimeMessage;

/**
 * DKIM helper methods: verification of DKIM signatures (RFC 6376, algorithm rsa-sha256), canonicalization, retrieval and caching of the public keys from DNS.
 * <p>
 * A message may have several DKIM signatures, which are verified independently. By default, a message is valid, if at least one signature is valid and its signing domain (d=)
 * matches the domain of the From header, as used by DMARC (see {@link DomainAlignment}).
 */
public final class DkimUtilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private DkimUtilities() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * The supported signature algorithm (a=).
	 */
	public static final String ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE = "rsa-sha256";
	/**
	 * JCA name of the signature algorithm.
	 */
	public static final String SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
	/**
	 * Name of the "relaxed" canonicalization algorithm.
	 */
	public static final String DKIM_SERIALIZATION_RELAXED_CODE = "relaxed";
	/**
	 * Name of the "simple" canonicalization algorithm.
	 */
	public static final String DKIM_SERIALIZATION_SIMPLE_CODE = "simple";

	/**
	 * Name of the DKIM signature header.
	 */
	static final String DKIM_SIGNATURE_HEADER_NAME = "DKIM-Signature";

	/**
	 * Maximum number of cached DomainKeys.
	 */
	private static final int MAXIMUM_CACHE_SIZE = 1000;

	/**
	 * Maximum number of DKIM signatures of a message, which are verified. Further signatures are ignored (protection against messages with a huge number of signatures, each needing a DNS lookup).
	 */
	public static final int MAXIMUM_SIGNATURES_TO_VERIFY = 10;

	/**
	 * Domain alignment used by {@link #checkDkimSignature(Message)} and {@link #verifyDkimSignature(Message)}: the domain of the From header, as used by DMARC.
	 */
	public static final DomainAlignment DEFAULT_DOMAIN_ALIGNMENT = DomainAlignment.FROM;

	/**
	 * Domain, which the signing domain (d=) of a valid signature must match. The signing domain must be the same as this domain or one of its parent domains.
	 */
	public enum DomainAlignment {
		/**
		 * The domain of the Return-Path header (envelope sender, bounce address). Mails of mailing services often use the domain of the service here.
		 */
		RETURN_PATH("Return-Path"),

		/**
		 * The domain of the From header, which is shown to the recipient, as used by DMARC (default)
		 */
		FROM("From"),

		/**
		 * Any signing domain is accepted
		 */
		NONE(null);

		/**
		 * Name of the header with the domain to match
		 */
		private final String headerName;

		/**
		 * Creates the constant.
		 *
		 * @param headerName name of the header with the domain to match, or null
		 */
		DomainAlignment(final String headerName) {
			this.headerName = headerName;
		}

		/**
		 * Returns the name of the header with the domain to match.
		 *
		 * @return the header name or null for {@link #NONE}
		 */
		public String getHeaderName() {
			return headerName;
		}
	}

	/**
	 * Cache of DomainKeys by DNS record name, limited in size (least recently used entries are removed)
	 */
	private static final Map<String, DomainKey> DOMAINKEY_CACHE = new DomainKeyCache();

	/**
	 * Matches the "b=" tag (not "bh=") of a DKIM-Signature header value and its value up to the next ";" or the end
	 */
	private static final Pattern SIGNATURE_VALUE_PATTERN = Pattern.compile("((?:^|;)\\s*b\\s*=)[^;]*");
	/**
	 * Pattern for the quoted or unquoted strings of a DNS TXT record value.
	 */
	private static final Pattern RECORD_PATTERN = Pattern.compile("(?:\"(.*?)\"(?: |$))|(?:'(.*?)'(?: |$))|(?:(.*?)(?: |$))");
	/**
	 * Default time to live of cached DomainKeys in milliseconds (2 hours).
	 */
	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;
	/**
	 * Time to live of cached DomainKeys in milliseconds.
	 */
	private static long cacheTtl = DEFAULT_CACHE_TTL;

	/**
	 * Returns the time to live of cached DomainKeys.
	 *
	 * @return time to live in milliseconds, 0 for no caching
	 */
	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	/**
	 * Sets the time to live of cached DomainKeys.
	 *
	 * @param cacheTtl time to live in milliseconds, 0 for no caching, negative values for the default of 2 hours
	 */
	public static synchronized void setCacheTtl(final long cacheTtl) {
		DkimUtilities.cacheTtl = cacheTtl < 0 ? DEFAULT_CACHE_TTL : cacheTtl;
	}

	/**
	 * Retrieves the DomainKey for a signing domain and selector from DNS or from the cache.
	 *
	 * @param signingDomain the signing domain (d=)
	 * @param selector the key selector (s=)
	 * @return the DomainKey
	 * @throws Exception if the DNS lookup fails or the key record is invalid
	 */
	public static synchronized DomainKey getDomainKey(final String signingDomain, final String selector) throws Exception {
		return getDomainKey(getRecordName(signingDomain, selector));
	}

	/**
	 * Retrieves the DomainKey for a DNS record name from the cache or from DNS.
	 *
	 * @param recordName DNS record name ("selector._domainkey.domain")
	 * @return the DomainKey
	 * @throws Exception if the DNS lookup fails or the key record is invalid
	 */
	private static synchronized DomainKey getDomainKey(final String recordName) throws Exception {
		DomainKey domainKey = DOMAINKEY_CACHE.get(recordName);
		if (null != domainKey && 0 != cacheTtl && isRecent(domainKey)) {
			return domainKey;
		} else {
			domainKey = new DomainKey(getTags(recordName));
			DOMAINKEY_CACHE.put(recordName, domainKey);
			return domainKey;
		}
	}

	/**
	 * Stores a DomainKey in the cache, e.g. for tests or for keys, which are not retrieved via DNS.
	 *
	 * @param signingDomain the signing domain (d=)
	 * @param selector the key selector (s=)
	 * @param domainKey the DomainKey
	 */
	static synchronized void cacheDomainKey(final String signingDomain, final String selector, final DomainKey domainKey) {
		DOMAINKEY_CACHE.put(getRecordName(signingDomain, selector), domainKey);
	}

	/**
	 * Removes all cached DomainKeys.
	 */
	public static synchronized void clearDomainKeyCache() {
		DOMAINKEY_CACHE.clear();
	}

	/**
	 * Checks whether a cached DomainKey is still within its time to live.
	 *
	 * @param domainKey the DomainKey
	 * @return true if the DomainKey may still be used
	 */
	private static boolean isRecent(final DomainKey domainKey) {
		return domainKey.getTimestamp() + cacheTtl > System.currentTimeMillis();
	}

	/**
	 * Retrieves the tags of a DKIM key record from DNS.
	 *
	 * @param recordName DNS record name
	 * @return the tags by tag name
	 * @throws Exception if the DNS lookup fails or the record is invalid
	 */
	private static Map<Character, String> getTags(final String recordName) throws Exception {
		final String recordValue = getValue(recordName);
		return parseDomainKeyTags(recordValue);
	}

	/**
	 * Parses the tags of a DKIM key record. Empty tag specifications are skipped, unknown tags with names longer than one character are ignored (RFC 6376, section 3.2).
	 *
	 * @param recordValue the record value, e.g. "v=DKIM1; k=rsa; p=..."
	 * @return the tags by tag name with trimmed values
	 * @throws Exception if a tag specification has no "="
	 */
	static Map<Character, String> parseDomainKeyTags(final String recordValue) throws Exception {
		final Map<Character, String> tags = new HashMap<>();
		for (final String tagSpec : recordValue.split(";")) {
			if (Utilities.isNotBlank(tagSpec)) {
				final String[] tagKeyValueParts = tagSpec.split("=", 2);
				if (tagKeyValueParts.length != 2 || Utilities.isBlank(tagKeyValueParts[0])) {
					throw new Exception("Invalid tag '" + tagSpec.trim() + "' found in DKIM key record: " + recordValue);
				}
				final String tagName = tagKeyValueParts[0].trim();
				if (tagName.length() == 1) {
					tags.put(tagName.charAt(0), tagKeyValueParts[1].trim());
				}
			}
		}
		return tags;
	}

	/**
	 * Reads the value of the TXT record from DNS. The lookup uses a timeout of 5 seconds and 2 retries.
	 *
	 * @param recordName DNS record name
	 * @return the unquoted record value
	 * @throws Exception if the lookup fails or no TXT record exists
	 */
	private static String getValue(final String recordName) throws Exception {
		try {
			final DirContext dnsContext = new InitialDirContext(getEnvironment());

			final Attributes attributes = dnsContext.getAttributes(recordName, new String[] { "TXT" });
			final Attribute txtRecord = attributes.get("txt");

			if (txtRecord == null) {
				throw new Exception("There is no TXT record available for " + recordName);
			}

			final StringBuilder builder = new StringBuilder();
			final NamingEnumeration<?> e = txtRecord.getAll();
			while (e.hasMore()) {
				if (builder.length() > 0) {
					builder.append(";");
				}
				builder.append((String) e.next());
			}

			final String value = builder.toString();
			if (value.isEmpty()) {
				throw new Exception("Value of RR " + recordName + " couldn't be retrieved");
			}

			return unquoteRecordValue(value);
		} catch (final NamingException ne) {
			throw new Exception("Selector lookup failed", ne);
		}
	}

	/**
	 * Joins the quoted or unquoted strings of a TXT record value.
	 *
	 * @param recordValue the TXT record value as returned by JNDI
	 * @return the joined value
	 * @throws Exception if the value is empty
	 */
	private static String unquoteRecordValue(final String recordValue) throws Exception {
		final Matcher recordMatcher = RECORD_PATTERN.matcher(recordValue);

		final StringBuilder builder = new StringBuilder();
		while (recordMatcher.find()) {
			for (int i = 1; i <= recordMatcher.groupCount(); i++) {
				final String match = recordMatcher.group(i);
				if (null != match) {
					builder.append(match);
				}
			}
		}

		final String unquotedRecordValue = builder.toString();
		if (null == unquotedRecordValue || 0 == unquotedRecordValue.length()) {
			throw new Exception("Unable to parse DKIM record: " + recordValue);
		}

		return unquotedRecordValue;
	}

	/**
	 * Returns the DNS record name of a DKIM key.
	 *
	 * @param signingDomain the signing domain
	 * @param selector the key selector
	 * @return "selector._domainkey.signingDomain"
	 */
	private static String getRecordName(final String signingDomain, final String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	/**
	 * Returns the JNDI environment for DNS lookups with timeouts.
	 *
	 * @return the JNDI environment
	 */
	private static Hashtable<String, String> getEnvironment() {
		final Hashtable<String, String> environment = new Hashtable<>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		// Prevent unbounded blocking on unresponsive or malicious DNS servers (DoS protection)
		environment.put("com.sun.jndi.dns.timeout.initial", "5000");
		environment.put("com.sun.jndi.dns.timeout.retries", "2");
		return environment;
	}

	/**
	 * Serializes header names for the "h=" tag, separated by ":" and folded into lines of limited length.
	 *
	 * @param headerNames the header names
	 * @param prefixLength number of characters already used in the first line
	 * @param maxHeaderLength maximum line length
	 * @return the serialized header names
	 */
	public static String serializeHeaderNames(final List<String> headerNames, final int prefixLength, final int maxHeaderLength) {
		final StringBuilder headerNamesSerialized = new StringBuilder();
		int currentLinePosition = prefixLength;
		for (int i = 0; i < headerNames.size(); i++) {
			final String headerName = headerNames.get(i);
			final boolean isLastHeaderName = ((i + 1) >= headerNames.size());
			if (headerNamesSerialized.length() == 0) {
				// first header without leading separator
				headerNamesSerialized.append(headerName);
				currentLinePosition += headerName.length();
			} else if (currentLinePosition + 1 + headerName.length() + (isLastHeaderName ? 0 : 1) > maxHeaderLength) {
				// header content would exceed limit, so linebreak is added
				headerNamesSerialized.append(":");
				headerNamesSerialized.append("\r\n\t ");
				headerNamesSerialized.append(headerName);
				currentLinePosition = 2 + headerName.length();
			} else {
				// simply adding separator and headername
				headerNamesSerialized.append(":");
				headerNamesSerialized.append(headerName);
				currentLinePosition += 1 + headerName.length();
			}
		}
		return headerNamesSerialized.toString();
	}

	/**
	 * Parses the tag list of a DKIM-Signature header value.
	 * Whitespace (including folding) is removed from tag names and from the values of the tags b, bh and h, other values are trimmed and their whitespace is compressed.
	 *
	 * @param dkimSignatureValue the header value
	 * @return the tags by tag name in order of appearance
	 * @throws Exception for tags without "=" or duplicate tags
	 */
	private static Map<String, String> parseDkimSignatureTags(final String dkimSignatureValue) throws Exception {
		final Map<String, String> tags = new LinkedHashMap<>();
		for (final String tagSpec : dkimSignatureValue.split(";")) {
			if (Utilities.isNotBlank(tagSpec)) {
				final int equalsIndex = tagSpec.indexOf('=');
				if (equalsIndex < 0) {
					throw new Exception("Invalid DKIM signature tag: " + tagSpec.trim());
				}
				final String tagName = removeWhitespace(tagSpec.substring(0, equalsIndex));
				String tagValue = tagSpec.substring(equalsIndex + 1);
				if ("b".equals(tagName) || "bh".equals(tagName) || "h".equals(tagName)) {
					tagValue = removeWhitespace(tagValue);
				} else {
					tagValue = tagValue.replaceAll("\\s+", " ").trim();
				}
				if (tags.containsKey(tagName)) {
					throw new Exception("Duplicate DKIM signature tag: " + tagName);
				}
				tags.put(tagName, tagValue);
			}
		}
		return tags;
	}

	/**
	 * Removes all whitespace including line breaks.
	 *
	 * @param value the value
	 * @return the value without whitespace
	 */
	private static String removeWhitespace(final String value) {
		return value.replaceAll("\\s+", "");
	}

	/**
	 * Canonicalizes a header (RFC 6376, section 3.4).
	 * "relaxed": lowercase name, unfolded value with compressed whitespace, no whitespace around the colon.
	 * "simple": "name: value" unchanged.
	 *
	 * @param useRelaxedCanonicalization true for "relaxed", false for "simple"
	 * @param headerName the header name
	 * @param headerValue the header value
	 * @return the canonicalized header without trailing CRLF
	 */
	public static String canonicalizeHeader(final boolean useRelaxedCanonicalization, final String headerName, final String headerValue) {
		if (useRelaxedCanonicalization) {
			// Locale.ROOT: header names must not be lowercased by locale specific rules (e.g. Turkish dotless i)
			return headerName.trim().toLowerCase(Locale.ROOT) + ":" + headerValue.replaceAll("\\s+", " ").trim();
		} else {
			return headerName + ": " + headerValue;
		}
	}

	/**
	 * Canonicalizes a complete header line ("Name: value", possibly folded) as it is written in the message.
	 * Simple canonicalization keeps the line unchanged, relaxed canonicalization unfolds and compresses it.
	 *
	 * @param useRelaxedCanonicalization true for "relaxed", false for "simple"
	 * @param headerLine the header line without trailing CRLF
	 * @return the canonicalized header line
	 */
	static String canonicalizeHeaderLine(final boolean useRelaxedCanonicalization, final String headerLine) {
		if (useRelaxedCanonicalization) {
			final int colonIndex = headerLine.indexOf(':');
			return canonicalizeHeader(true, headerLine.substring(0, colonIndex), headerLine.substring(colonIndex + 1));
		} else {
			return headerLine;
		}
	}

	/**
	 * Canonicalizes a message body (RFC 6376, section 3.4). Line breaks are normalized to CRLF first.
	 * "relaxed": whitespace at line ends is removed and other whitespace sequences are compressed, empty lines at the end are removed, an empty body stays empty.
	 * "simple": empty lines at the end are removed, an empty body becomes a single CRLF.
	 *
	 * @param useRelaxedCanonicalization true for "relaxed", false for "simple"
	 * @param body the body text (for binary content as ISO-8859-1 text) or null
	 * @return the canonicalized body
	 */
	public static String canonicalizeBody(final boolean useRelaxedCanonicalization, String body) {
		if (body != null) {
			// Normalize all line breaks to CRLF
			body = body.replace("\r\n", "\n").replace("\r", "\n").replace("\n", "\r\n");
		}

		if (useRelaxedCanonicalization) {
			if (body == null || body.isEmpty()) {
				return "";
			} else {
				if (!body.endsWith("\r\n")) {
					body += "\r\n";
				}
				body = body.replaceAll("[ \\t]+\r\n", "\r\n");
				body = body.replaceAll("[ \\t]+", " ");

				while (body.endsWith("\r\n\r\n")) {
					body = body.substring(0, body.length() - 2);
				}

				if ("\r\n".equals(body)) {
					body = "";
				}

				return body;
			}
		} else {
			if (body == null || body.isEmpty()) {
				return "\r\n";
			} else if (!body.endsWith("\r\n")) {
				return body + "\r\n";
			} else {
				while (body.endsWith("\r\n\r\n")) {
					body = body.substring(0, body.length() - 2);
				}
				return body;
			}
		}
	}

	/**
	 * Encodes a value in DKIM-Quoted-Printable (RFC 6376, section 2.11), as used for the "i=" tag.
	 * Printable ASCII characters except ";" and "=" are kept, all other bytes of the UTF-8 encoding are written as "=XX".
	 * Unlike MIME quoted-printable, no soft line breaks are inserted.
	 *
	 * @param value the value
	 * @return the encoded value
	 */
	public static String encodeDkimQuotedPrintable(final String value) {
		final StringBuilder encodedValue = new StringBuilder();
		for (final byte valueByte : value.getBytes(StandardCharsets.UTF_8)) {
			final int unsignedByte = valueByte & 0xFF;
			if (unsignedByte >= 0x21 && unsignedByte <= 0x7E && unsignedByte != ';' && unsignedByte != '=') {
				encodedValue.append((char) unsignedByte);
			} else {
				encodedValue.append('=').append(String.format("%02X", unsignedByte));
			}
		}
		return encodedValue.toString();
	}

	/**
	 * Decodes a DKIM-Quoted-Printable value (RFC 6376, section 2.11). Whitespace is ignored.
	 *
	 * @param value the encoded value
	 * @return the decoded value (UTF-8)
	 * @throws Exception for invalid "=XX" sequences
	 */
	public static String decodeDkimQuotedPrintable(final String value) throws Exception {
		final ByteArrayOutputStream decodedBytes = new ByteArrayOutputStream();
		final String compactValue = removeWhitespace(value);
		for (int i = 0; i < compactValue.length(); i++) {
			final char nextChar = compactValue.charAt(i);
			if (nextChar == '=') {
				if (i + 2 >= compactValue.length()) {
					throw new Exception("Invalid DKIM-Quoted-Printable value: " + value);
				}
				final int high = Character.digit(compactValue.charAt(i + 1), 16);
				final int low = Character.digit(compactValue.charAt(i + 2), 16);
				if (high < 0 || low < 0) {
					throw new Exception("Invalid DKIM-Quoted-Printable value: " + value);
				}
				decodedBytes.write((high << 4) | low);
				i += 2;
			} else {
				decodedBytes.write(nextChar);
			}
		}
		return new String(decodedBytes.toByteArray(), StandardCharsets.UTF_8);
	}

	/**
	 * Checks the DKIM signatures of a message: valid, if at least one signature is valid and its signing domain (d=) matches the domain of the From header
	 * ({@link DomainAlignment#FROM}, as used by DMARC).
	 * Use {@link #verifyDkimSignatures(Message, DomainAlignment)} to get the details of all signatures.
	 *
	 * @param message the received message
	 * @return null if the message has no DKIM signature, true if a valid matching signature exists, otherwise false
	 */
	public static Boolean checkDkimSignature(final Message message) {
		try {
			return verifyDkimSignature(message);
		} catch (@SuppressWarnings("unused") final Exception e) {
			return false;
		}
	}

	/**
	 * Verifies the DKIM signatures of a message and reports the reasons of a failed verification by an exception.
	 * The message is valid, if at least one signature is valid and its signing domain (d=) matches the domain of the From header
	 * ({@link DomainAlignment#FROM}, as used by DMARC).
	 *
	 * @param message the received message
	 * @return null if the message has no DKIM signature, true if a valid matching signature exists
	 * @throws Exception if no valid matching signature exists, with the reasons of all signatures as message
	 */
	public static Boolean verifyDkimSignature(final Message message) throws Exception {
		final DkimVerificationResult result = verifyDkimSignatures(message, DEFAULT_DOMAIN_ALIGNMENT);
		if (!result.isSigned()) {
			return null;
		} else if (result.isValid()) {
			return true;
		} else {
			throw new Exception(result.getErrorMessage());
		}
	}

	/**
	 * Verifies all DKIM signatures of a message (at most {@link #MAXIMUM_SIGNATURES_TO_VERIFY}, from top to bottom).
	 * <p>
	 * As defined in RFC 6376, each signature is verified independently and invalid signatures do not make the message invalid.
	 * The message is valid, if at least one signature is valid and its signing domain (d=) matches the domain required by the given alignment.
	 * <p>
	 * For a MimeMessage the raw header lines and the raw (still transfer encoded) body are used, as required for the hashes.
	 * Signed header names without (further) header instance are allowed (e.g. "over-signing" to prevent adding headers later).
	 *
	 * @param message the received message
	 * @param domainAlignment which domain a valid signature must match
	 * @return the results of all verified signatures
	 * @throws Exception if the headers or the body of the message cannot be read
	 */
	public static DkimVerificationResult verifyDkimSignatures(final Message message, final DomainAlignment domainAlignment) throws Exception {
		final List<String> headerLines = getHeaderLines(message);

		final List<Integer> dkimSignatureHeaderIndexes = new ArrayList<>();
		for (int i = 0; i < headerLines.size(); i++) {
			if (DKIM_SIGNATURE_HEADER_NAME.equalsIgnoreCase(getHeaderName(headerLines.get(i))) && Utilities.isNotBlank(getHeaderValue(headerLines.get(i)))) {
				dkimSignatureHeaderIndexes.add(i);
			}
		}
		if (dkimSignatureHeaderIndexes.isEmpty()) {
			return new DkimVerificationResult(new ArrayList<>());
		}

		// The domain, which a valid signature must match
		String alignmentDomain = null;
		String alignmentError = null;
		try {
			alignmentDomain = getAlignmentDomain(headerLines, domainAlignment);
		} catch (final Exception e) {
			alignmentError = e.getMessage();
		}

		final byte[] rawBodyBytes = getRawBody(message);

		final List<DkimSignatureResult> signatureResults = new ArrayList<>();
		for (int signatureNumber = 0; signatureNumber < dkimSignatureHeaderIndexes.size(); signatureNumber++) {
			if (signatureNumber >= MAXIMUM_SIGNATURES_TO_VERIFY) {
				// Protection against messages with a huge number of signatures (each needs a DNS lookup)
				signatureResults.add(new DkimSignatureResult(null, null, false, false, "Not verified, because the maximum number of " + MAXIMUM_SIGNATURES_TO_VERIFY + " verified signatures was exceeded"));
				continue;
			}

			final int dkimSignatureHeaderIndex = dkimSignatureHeaderIndexes.get(signatureNumber);
			final String dkimSignatureHeaderLine = headerLines.get(dkimSignatureHeaderIndex);

			// The signature being verified is not part of the signed header fields itself (RFC 6376, section 3.7)
			final List<String> otherHeaderLines = new ArrayList<>(headerLines);
			otherHeaderLines.remove(dkimSignatureHeaderIndex);

			String domain = null;
			String selector = null;
			try {
				final Map<String, String> signatureValues = parseDkimSignatureTags(getHeaderValue(dkimSignatureHeaderLine));
				domain = signatureValues.get("d");
				selector = signatureValues.get("s");
				verifySingleSignature(otherHeaderLines, dkimSignatureHeaderLine, signatureValues, rawBodyBytes);
			} catch (final Exception e) {
				signatureResults.add(new DkimSignatureResult(domain, selector, false, false, e.getMessage()));
				continue;
			}

			if (domainAlignment == DomainAlignment.NONE) {
				signatureResults.add(new DkimSignatureResult(domain, selector, true, true, null));
			} else if (alignmentDomain == null) {
				signatureResults.add(new DkimSignatureResult(domain, selector, true, false, alignmentError));
			} else if (isSameOrSubdomain(alignmentDomain, domain)) {
				signatureResults.add(new DkimSignatureResult(domain, selector, true, true, null));
			} else {
				signatureResults.add(new DkimSignatureResult(domain, selector, true, false, "DKIM signature domain '" + domain + "' does not match " + domainAlignment.getHeaderName() + " domain '" + alignmentDomain + "'"));
			}
		}
		return new DkimVerificationResult(signatureResults);
	}

	/**
	 * Returns the domain of the Return-Path or From header, which a valid signature must match.
	 *
	 * @param headerLines the header lines of the message
	 * @param domainAlignment which header to use
	 * @return the domain or null for {@link DomainAlignment#NONE}
	 * @throws Exception if the header is missing, occurs several times or has no valid email address
	 */
	private static String getAlignmentDomain(final List<String> headerLines, final DomainAlignment domainAlignment) throws Exception {
		if (domainAlignment == DomainAlignment.NONE) {
			return null;
		}

		String headerValue = null;
		for (final String headerLine : headerLines) {
			if (domainAlignment.getHeaderName().equalsIgnoreCase(getHeaderName(headerLine))) {
				if (headerValue != null) {
					throw new Exception("Multiple " + domainAlignment.getHeaderName() + " found");
				} else {
					headerValue = getHeaderValue(headerLine).trim();
				}
			}
		}
		if (Utilities.isBlank(headerValue)) {
			throw new Exception("This message is missing the mandatory " + domainAlignment.getHeaderName() + " header value");
		}

		final String emailAddress;
		try {
			final InternetAddress[] addresses = InternetAddress.parseHeader(headerValue, false);
			if (addresses.length != 1) {
				throw new Exception("Exactly one address expected");
			}
			emailAddress = addresses[0].getAddress();
		} catch (final Exception e) {
			throw new Exception(domainAlignment.getHeaderName() + " header value '" + headerValue + "' is invalid: " + e.getMessage(), e);
		}

		final String domain;
		try {
			domain = MailUtilities.getDomainFromEmail(emailAddress);
		} catch (final Exception e) {
			throw new Exception(domainAlignment.getHeaderName() + " header value '" + headerValue + "' is invalid: " + e.getMessage(), e);
		}
		if (Utilities.isBlank(domain)) {
			throw new Exception(domainAlignment.getHeaderName() + " header value has no domain");
		}
		return domain;
	}

	/**
	 * Verifies one DKIM signature.
	 *
	 * @param headerLines the header lines of the message without the DKIM-Signature header being verified
	 * @param dkimSignatureHeaderLine the DKIM-Signature header line being verified
	 * @param signatureValues the parsed tags of the DKIM-Signature header
	 * @param rawBodyBytes the raw (still transfer encoded) body
	 * @throws Exception if the signature is invalid, with the reason as message
	 */
	private static void verifySingleSignature(final List<String> headerLines, final String dkimSignatureHeaderLine, final Map<String, String> signatureValues, final byte[] rawBodyBytes) throws Exception {
		final String dkimSignatureVersion = signatureValues.get("v");
		if (Utilities.isBlank(dkimSignatureVersion)) {
			throw new Exception("DKIM signature is missing the mandatory version(v) value");
		} else if (!"1".equals(dkimSignatureVersion)) {
			throw new Exception("DKIM signature has an unknown version(v) value: " + dkimSignatureVersion);
		}

		final String dkimSignatureAlgorithm = signatureValues.get("a");
		if (Utilities.isBlank(dkimSignatureAlgorithm)) {
			throw new Exception("DKIM signature is missing the mandatory algorithm(a) value");
		} else if (!ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE.equalsIgnoreCase(dkimSignatureAlgorithm)) {
			throw new Exception("DKIM signature used an unsupported algorithm: " + dkimSignatureAlgorithm);
		}

		final String dkimSignatureDomain = signatureValues.get("d");
		if (Utilities.isBlank(dkimSignatureDomain)) {
			throw new Exception("DKIM signature is missing the mandatory domain(d) value");
		}

		final String selector = signatureValues.get("s");
		if (Utilities.isBlank(selector)) {
			throw new Exception("DKIM signature is missing the mandatory selector(s) value");
		}

		final String dkimSignatureBodyHash = signatureValues.get("bh");
		if (Utilities.isBlank(dkimSignatureBodyHash)) {
			throw new Exception("DKIM signature is missing the mandatory bodyHash(bh) value");
		}

		final String headersIncludedInSignature = signatureValues.get("h");
		if (Utilities.isBlank(headersIncludedInSignature)) {
			throw new Exception("DKIM signature is missing the mandatory headersIncludedInSignature(h) value");
		}

		final String dkimSignatureBytesBase64 = signatureValues.get("b");
		if (Utilities.isBlank(dkimSignatureBytesBase64)) {
			throw new Exception("DKIM signature is missing the mandatory dkimSignatureBytes(b) value");
		}

		// The identity (i=) must be in the signing domain or one of its subdomains
		final String identity = signatureValues.get("i");
		String identityDomain = null;
		if (identity != null) {
			final String decodedIdentity = decodeDkimQuotedPrintable(identity);
			if (!decodedIdentity.contains("@")) {
				throw new Exception("DKIM signature has an invalid identity(i) value: " + identity);
			}
			identityDomain = decodedIdentity.substring(decodedIdentity.lastIndexOf('@') + 1);
			if (!isSameOrSubdomain(identityDomain, dkimSignatureDomain)) {
				throw new Exception("DKIM signature identity(i) domain '" + identityDomain + "' is not the signing domain '" + dkimSignatureDomain + "' or one of its subdomains");
			}
		}

		// Expiration (x=)
		final String expiration = signatureValues.get("x");
		if (Utilities.isNotBlank(expiration)) {
			final long expirationSeconds;
			try {
				expirationSeconds = Long.parseLong(expiration);
			} catch (final NumberFormatException e) {
				throw new Exception("DKIM signature has an invalid expiration(x) value: " + expiration, e);
			}
			if (expirationSeconds * 1000L < System.currentTimeMillis()) {
				throw new Exception("DKIM signature has expired");
			}
		}

		final String canonicalization = signatureValues.get("c");
		final boolean useRelaxedHeaderCanonicalization;
		final boolean useRelaxedBodyCanonicalization;
		if (Utilities.isBlank(canonicalization)) {
			// RFC 6376: default canonicalization is "simple/simple"
			useRelaxedHeaderCanonicalization = false;
			useRelaxedBodyCanonicalization = false;
		} else {
			final String[] canonicalizationParts = canonicalization.toLowerCase(Locale.ROOT).split("/", -1);
			if (canonicalizationParts.length > 2) {
				throw new Exception("DKIM signature has an invalid canonicalization(c) value: " + canonicalization);
			}
			useRelaxedHeaderCanonicalization = parseCanonicalizationAlgorithm(canonicalizationParts[0], canonicalization);
			// RFC 6376: if only one algorithm is given, it is used for the header, the body uses "simple"
			useRelaxedBodyCanonicalization = canonicalizationParts.length == 2 ? parseCanonicalizationAlgorithm(canonicalizationParts[1], canonicalization) : false;
		}

		final DomainKey domainKey;
		try {
			domainKey = getDomainKey(dkimSignatureDomain, selector);
		} catch (final Exception e) {
			throw new Exception("Error while acquiring DKIM key from domain '" + dkimSignatureDomain + "' (selector: " + selector + "): " + e.getMessage(), e);
		}
		final String keyFlags = domainKey.getTags().get('t');
		if (keyFlags != null && identityDomain != null && Arrays.asList(removeWhitespace(keyFlags).split(":")).contains("s") && !identityDomain.equalsIgnoreCase(dkimSignatureDomain)) {
			throw new Exception("DKIM key does not allow subdomains in the identity(i) value (t=s)");
		}

		// Body hash: computed over the raw (still transfer encoded) body
		String canonicalBody = canonicalizeBody(useRelaxedBodyCanonicalization, new String(rawBodyBytes, StandardCharsets.ISO_8859_1));
		final String bodyLength = signatureValues.get("l");
		if (Utilities.isNotBlank(bodyLength)) {
			final long bodyLengthValue;
			try {
				bodyLengthValue = Long.parseLong(bodyLength);
			} catch (final NumberFormatException e) {
				throw new Exception("DKIM signature has an invalid body length(l) value: " + bodyLength, e);
			}
			if (bodyLengthValue < 0 || bodyLengthValue > canonicalBody.length()) {
				throw new Exception("DKIM signature body length(l) value exceeds the body length: " + bodyLength);
			}
			canonicalBody = canonicalBody.substring(0, (int) bodyLengthValue);
		}
		final byte[] bodyHashBytes = MessageDigest.getInstance("SHA-256").digest(canonicalBody.getBytes(StandardCharsets.ISO_8859_1));
		final String bodyHashBase64String = Base64.getEncoder().encodeToString(bodyHashBytes);
		if (!dkimSignatureBodyHash.equals(bodyHashBase64String)) {
			throw new Exception("Bodyhash value of DKIM signature '" + dkimSignatureBodyHash + "' does not match bodyhash of message '" + bodyHashBase64String + "' in mode '" + (useRelaxedBodyCanonicalization ? DKIM_SERIALIZATION_RELAXED_CODE : DKIM_SERIALIZATION_SIMPLE_CODE) + "'");
		}

		// Signed header fields: for multiple occurrences of a header name, the instances are used from the bottom up.
		// Names without (further) instance are allowed (e.g. to prevent adding headers later) and contribute nothing.
		final Map<String, LinkedList<String>> headerLinesByName = getHeaderLinesByName(headerLines);
		boolean fromHeaderIsIncluded = false;
		final StringBuilder serializedHeaderData = new StringBuilder();
		for (final String headerName : headersIncludedInSignature.split(":")) {
			if ("from".equalsIgnoreCase(headerName)) {
				fromHeaderIsIncluded = true;
			}
			final LinkedList<String> availableHeaderLines = headerLinesByName.get(headerName.toLowerCase(Locale.ROOT));
			if (availableHeaderLines != null && !availableHeaderLines.isEmpty()) {
				serializedHeaderData.append(canonicalizeHeaderLine(useRelaxedHeaderCanonicalization, availableHeaderLines.removeLast()));
				serializedHeaderData.append("\r\n");
			}
		}

		if (!fromHeaderIsIncluded) {
			throw new Exception("Mandatory header 'from' is not included in headers for dkim signature");
		}

		// The DKIM-Signature header itself is signed with an empty value of the "b=" tag, wherever this tag is placed
		serializedHeaderData.append(canonicalizeHeaderLine(useRelaxedHeaderCanonicalization, removeSignatureValue(dkimSignatureHeaderLine)));

		final Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM_NAME);
		signature.initVerify(domainKey.getPublicKey());
		signature.update(serializedHeaderData.toString().getBytes(StandardCharsets.UTF_8));
		final byte[] signatureBytes;
		try {
			signatureBytes = Base64.getDecoder().decode(dkimSignatureBytesBase64);
		} catch (final IllegalArgumentException e) {
			throw new Exception("DKIM signature has an invalid dkimSignatureBytes(b) value", e);
		}
		if (!signature.verify(signatureBytes)) {
			throw new Exception("DKIM signature does not match the signed header data");
		}
	}

	/**
	 * Parses one canonicalization algorithm name.
	 *
	 * @param canonicalizationAlgorithm "relaxed" or "simple"
	 * @param canonicalization the complete c= value for the error message
	 * @return true for "relaxed", false for "simple"
	 * @throws Exception for other values
	 */
	private static boolean parseCanonicalizationAlgorithm(final String canonicalizationAlgorithm, final String canonicalization) throws Exception {
		if (DKIM_SERIALIZATION_RELAXED_CODE.equals(canonicalizationAlgorithm)) {
			return true;
		} else if (DKIM_SERIALIZATION_SIMPLE_CODE.equals(canonicalizationAlgorithm)) {
			return false;
		} else {
			throw new Exception("DKIM signature has an invalid canonicalization(c) value: " + canonicalization);
		}
	}

	/**
	 * Removes the value of the "b=" tag from a DKIM-Signature header line, keeping all other tags and their order.
	 *
	 * @param dkimSignatureHeaderLine the header line
	 * @return the header line with empty "b=" value
	 */
	static String removeSignatureValue(final String dkimSignatureHeaderLine) {
		final int colonIndex = dkimSignatureHeaderLine.indexOf(':');
		final String headerValue = dkimSignatureHeaderLine.substring(colonIndex + 1);
		final Matcher matcher = SIGNATURE_VALUE_PATTERN.matcher(headerValue);
		return dkimSignatureHeaderLine.substring(0, colonIndex + 1) + matcher.replaceFirst("$1");
	}

	/**
	 * Checks whether a domain is the same as or a subdomain of another domain (case insensitive).
	 *
	 * @param domain the domain to check
	 * @param parentDomain the parent domain
	 * @return true for the same domain or a subdomain
	 */
	private static boolean isSameOrSubdomain(final String domain, final String parentDomain) {
		final String domainLower = domain.toLowerCase(Locale.ROOT);
		final String parentDomainLower = parentDomain.toLowerCase(Locale.ROOT);
		return domainLower.equals(parentDomainLower) || domainLower.endsWith("." + parentDomainLower);
	}

	/**
	 * Returns the header lines of a message as they are stored ("Name: value", possibly folded).
	 *
	 * @param message the message
	 * @return the header lines in order of appearance
	 * @throws MessagingException if the headers cannot be read
	 */
	private static List<String> getHeaderLines(final Message message) throws MessagingException {
		final List<String> headerLines = new ArrayList<>();
		if (message instanceof MimeMessage) {
			headerLines.addAll(Collections.list(((MimeMessage) message).getAllHeaderLines()));
		} else {
			for (final Header header : Collections.list(message.getAllHeaders())) {
				headerLines.add(header.getName() + ": " + header.getValue());
			}
		}
		return headerLines;
	}

	/**
	 * Returns the name of a header line.
	 *
	 * @param headerLine the header line
	 * @return the header name
	 */
	static String getHeaderName(final String headerLine) {
		final int colonIndex = headerLine.indexOf(':');
		return colonIndex < 0 ? headerLine.trim() : headerLine.substring(0, colonIndex).trim();
	}

	/**
	 * Returns the value of a header line (everything after the first colon, unchanged).
	 *
	 * @param headerLine the header line
	 * @return the header value
	 */
	private static String getHeaderValue(final String headerLine) {
		final int colonIndex = headerLine.indexOf(':');
		return colonIndex < 0 ? "" : headerLine.substring(colonIndex + 1);
	}

	/**
	 * Groups header lines by their lowercase header name, keeping the order of occurrence.
	 *
	 * @param headerLines the header lines
	 * @return the header lines by lowercase name
	 */
	static Map<String, LinkedList<String>> getHeaderLinesByName(final List<String> headerLines) {
		final Map<String, LinkedList<String>> headerLinesByName = new HashMap<>();
		for (final String headerLine : headerLines) {
			headerLinesByName.computeIfAbsent(getHeaderName(headerLine).toLowerCase(Locale.ROOT), k -> new LinkedList<>()).add(headerLine);
		}
		return headerLinesByName;
	}

	/**
	 * Returns the raw body of a message, still in its transfer encoding (quoted-printable, base64), as needed for the body hash.
	 *
	 * @param message the message
	 * @return the raw body data
	 * @throws Exception if the body cannot be read
	 */
	private static byte[] getRawBody(final Message message) throws Exception {
		if (message instanceof MimeMessage) {
			try (InputStream inputStream = ((MimeMessage) message).getRawInputStream()) {
				return IoUtilities.toByteArray(inputStream);
			}
		} else {
			try (InputStream inputStream = message.getInputStream()) {
				return IoUtilities.toByteArray(inputStream);
			}
		}
	}

	/**
	 * Map of DomainKeys, limited to {@link #MAXIMUM_CACHE_SIZE} entries by removing the least recently used entry.
	 */
	private static final class DomainKeyCache extends LinkedHashMap<String, DomainKey> {
		/**
		 * Serialization version.
		 */
		private static final long serialVersionUID = 4123581792716409474L;

		/**
		 * Creates an empty cache with access order.
		 */
		private DomainKeyCache() {
			super(16, 0.75f, true);
		}

		@Override
		protected boolean removeEldestEntry(final Map.Entry<String, DomainKey> eldest) {
			return size() > MAXIMUM_CACHE_SIZE;
		}
	}
}
