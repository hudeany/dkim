package de.soderer.utilities.mail.dkim;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.Signature;
import java.util.Base64;
import java.util.Collections;
import java.util.HashMap;
import java.util.Hashtable;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.Header;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.internet.InternetAddress;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.Attribute;
import javax.naming.directory.Attributes;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;

import de.soderer.utilities.mail.dkim.utilities.IoUtilities;
import de.soderer.utilities.mail.dkim.utilities.MailUtilities;
import de.soderer.utilities.mail.dkim.utilities.TextUtilities;
import de.soderer.utilities.mail.dkim.utilities.TextUtilities.LineBreak;
import de.soderer.utilities.mail.dkim.utilities.Utilities;

public final class DkimUtilities {
	public static final String ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE = "rsa-sha256";
	public static final String SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
	public static final String DKIM_SERIALIZATION_RELAXED_CODE = "relaxed";
	public static final String DKIM_SERIALIZATION_SIMPLE_CODE = "simple";

	private static final Map<String, DomainKey> DOMAINKEY_CACHE = new HashMap<>();
	private static final Pattern RECORD_PATTERN = Pattern.compile("(?:\"(.*?)\"(?: |$))|(?:'(.*?)'(?: |$))|(?:(.*?)(?: |$))");
	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;
	private static long cacheTtl = DEFAULT_CACHE_TTL;

	public static synchronized long getCacheTtl() {
		return cacheTtl;
	}

	public static synchronized void setCacheTtl(long cacheTtl) {
		if (cacheTtl < 0) {
			cacheTtl = DEFAULT_CACHE_TTL;
		}
		DkimUtilities.cacheTtl = cacheTtl;
	}

	/**
	 * Retrieves the DomainKey for the given signing domain and selector
	 */
	public static synchronized DomainKey getDomainKey(final String signingDomain, final String selector) throws Exception {
		return getDomainKey(getRecordName(signingDomain, selector));
	}

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

	private static boolean isRecent(final DomainKey domainKey) {
		return domainKey.getTimestamp() + cacheTtl > System.currentTimeMillis();
	}

	private static Map<Character, String> getTags(final String recordName) throws Exception {
		final Map<Character, String> tags = new HashMap<>();

		final String recordValue = getValue(recordName);

		for (String tag : recordValue.split(";")) {
			try {
				tag = tag.trim();
				final String[] tagKeyValueParts = tag.split("=", 2);
				if (tagKeyValueParts.length == 2 && tagKeyValueParts[0].length() == 1) {
					tags.put(tagKeyValueParts[0].charAt(0), tagKeyValueParts[1]);
				} else {
					throw new Exception("Invalid tag found in recordValue: " + recordValue);
				}
			} catch (final IndexOutOfBoundsException e) {
				throw new Exception("The tag " + tag + " in RR " + recordName + " couldn't be decoded.", e);
			}
		}
		return tags;
	}

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

	private static String getRecordName(final String signingDomain, final String selector) {
		return selector + "._domainkey." + signingDomain;
	}

	private static Hashtable<String, String> getEnvironment() {
		final Hashtable<String, String> environment = new Hashtable<>();
		environment.put("java.naming.factory.initial", "com.sun.jndi.dns.DnsContextFactory");
		return environment;
	}

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

	private static Map<String, String> parseDkimSignatureProperties(String propertiesData) {
		propertiesData = propertiesData.replace(" ", "").replace("\t", "").replace("\n", "").replace("\r", "");
		final Map<String, String> returnMap = new HashMap<>();
		for (final String keyValueString : propertiesData.split(";")) {
			final String[] parts = keyValueString.split("=", 2);
			returnMap.put(parts[0], parts[1]);
		}
		return returnMap;
	}

	public static String canonicalizeHeader(final boolean useRelaxedCanonicalization, final String headerName, final String headerValue) {
		if (useRelaxedCanonicalization) {
			return headerName.trim().toLowerCase() + ":" + headerValue.replaceAll("\\s+", " ").trim();
		} else {
			return headerName + ": " + headerValue;
		}
	}

	public static String canonicalizeBody(final boolean useRelaxedCanonicalization, String body) {
		body = TextUtilities.normalizeLineBreaks(body, LineBreak.Windows);

		if (useRelaxedCanonicalization) {
			if (body == null) {
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
			if (body == null) {
				return "\r\n";
			} else {
				if (!body.endsWith("\r\n")) {
					return body + "\r\n";
				} else {
					while (body.endsWith("\r\n\r\n")) {
						body = body.substring(0, body.length() - 2);
					}

					return body;
				}
			}
		}
	}

	public static Boolean checkDkimSignature(final Message message) {
		try {
			String returnPath = null;
			String dkimSignature = null;
			for (final Header header : Collections.list(message.getAllHeaders())) {
				if ("Return-Path".equalsIgnoreCase(header.getName())) {
					if (returnPath != null) {
						throw new Exception("Multiple Return-Path found");
					} else {
						returnPath = header.getValue();
					}
				}

				if ("DKIM-Signature".equalsIgnoreCase(header.getName())) {
					if (dkimSignature != null) {
						throw new Exception("Multiple DKIM signature found");
					} else {
						dkimSignature = header.getValue();
					}
				}
			}
			if (dkimSignature == null || dkimSignature.trim().length() == 0) {
				return null;
			} else {
				if (returnPath == null || returnPath.trim().length() == 0) {
					throw new Exception("This message is missing the mandatory Return-Path header value");
				} else if (returnPath.contains("<")) {
					final InternetAddress returnPathAddress = new InternetAddress(returnPath);
					returnPath = returnPathAddress.getAddress();
				}

				final Map<String, String> signatureValues = DkimUtilities.parseDkimSignatureProperties(dkimSignature);

				final String dkimSignatureVersion = signatureValues.get("v");
				if (Utilities.isBlank(dkimSignatureVersion)) {
					throw new Exception("DKIM signature is missing the mandatory version(v) value");
				} else if (!"1".equals(dkimSignatureVersion)) {
					throw new Exception("DKIM signature has an unkown version(v) value: " + dkimSignatureVersion);
				}

				final String dkimSignatureAlgorithm = signatureValues.get("a");
				if (Utilities.isBlank(dkimSignatureAlgorithm)) {
					throw new Exception("DKIM signature is missing the mandatory algorithm(a) value");
				} else if (!DkimUtilities.ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE.equalsIgnoreCase(dkimSignatureAlgorithm)) {
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

				String returnPathDomain = null;
				try {
					returnPathDomain = MailUtilities.getDomainFromEmail(returnPath);
				} catch (final Exception e) {
					throw new Exception("Return-Path header value '" + returnPath + "' is invalid: " + e.getMessage());
				}
				if (Utilities.isBlank(returnPathDomain)) {
					throw new Exception("Return-Path header value has no domain");
				} else if (!returnPathDomain.equals(dkimSignatureDomain)) {
					throw new Exception("DKIM signature domain '" + dkimSignatureDomain + "' does not match Return-Path domain '" + returnPathDomain + "'");
				}

				final DomainKey domainKey;
				try {
					domainKey = DkimUtilities.getDomainKey(dkimSignatureDomain, selector);
				} catch (final Exception e) {
					throw new Exception("Error while aquiring DKIM key from domain '" + dkimSignatureDomain + "' (selector: " + selector + "): " + e.getMessage());
				}
				if (Utilities.isBlank(returnPathDomain)) {
					throw new Exception("Return-Path header value has no domain");
				}

				final String cononicalization = signatureValues.get("c");
				if (Utilities.isBlank(cononicalization)) {
					throw new Exception("DKIM signature is missing the mandatory cononicalization(c) value");
				}
				final boolean useRelaxedHeaderCanonicalization = cononicalization.toLowerCase().startsWith("relaxed/");
				final boolean useRelaxedBodyCanonicalization = cononicalization.toLowerCase().endsWith("/relaxed");

				MessageDigest bodyHashingMessageDigest;
				try {
					bodyHashingMessageDigest = MessageDigest.getInstance("sha-256");
				} catch (final NoSuchAlgorithmException e) {
					throw new MessagingException("Unknown hashing algorithm: sha-256", e);
				}
				final String canonicalBody;
				try (InputStream inputStream = message.getInputStream()) {
					canonicalBody = DkimUtilities.canonicalizeBody(useRelaxedBodyCanonicalization, IoUtilities.toString(inputStream, StandardCharsets.UTF_8));
				}
				final byte[] bodyHashBytes = bodyHashingMessageDigest.digest(canonicalBody.getBytes(StandardCharsets.UTF_8));
				final String bodyHashBase64String = Base64.getEncoder().encodeToString(bodyHashBytes).replace("\r", "").replace("\n", "");

				if (!dkimSignatureBodyHash.equals(bodyHashBase64String)) {
					throw new Exception("Bodyhash value of DKIM signature '" + dkimSignatureBodyHash + "' does not match bodyhash of message '" + bodyHashBase64String + "' in mode '" + (useRelaxedHeaderCanonicalization ? DkimUtilities.DKIM_SERIALIZATION_RELAXED_CODE : DkimUtilities.DKIM_SERIALIZATION_SIMPLE_CODE) + "'");
				}

				boolean fromHeaderIsIncluded = false;
				final StringBuilder serializedHeaderData = new StringBuilder();
				for (final String headerName : headersIncludedInSignature.split(":")) {
					if ("from".equalsIgnoreCase(headerName)) {
						fromHeaderIsIncluded = true;
					}

					final String[] headers = message.getHeader(headerName);
					if (headers == null) {
						throw new Exception("Invalid missing header value for '" + headerName + "'");
					} else if (headers.length > 1) {
						throw new Exception("Invalid multiple header value for '" + headerName + "'");
					} else {
						serializedHeaderData.append(DkimUtilities.canonicalizeHeader(useRelaxedHeaderCanonicalization, headerName, headers[0]));
						serializedHeaderData.append("\r\n");
					}
				}

				if (!fromHeaderIsIncluded) {
					throw new MessagingException("Mandatory header 'from' is not included in headers for dkim signature");
				}

				final String dkimSignatureWithoutSignatureBytesBase64 = dkimSignature.substring(0, dkimSignature.indexOf("b=") + 2);
				serializedHeaderData.append(DkimUtilities.canonicalizeHeader(useRelaxedHeaderCanonicalization, "dkim-signature", dkimSignatureWithoutSignatureBytesBase64));

				final Signature signature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
				signature.initVerify(domainKey.getPublicKey());
				signature.update(serializedHeaderData.toString().getBytes(StandardCharsets.UTF_8));
				final boolean result = signature.verify(Utilities.decodeBase64(dkimSignatureBytesBase64));
				return result;
			}
		} catch (final Exception e) {
			e.printStackTrace();
			return false;
		}
	}
}
