package de.soderer.utilities.mail.dkim;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.io.Reader;
import java.nio.charset.Charset;
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

public final class DkimUtilities {
	public static final String ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE = "rsa-sha256";
	public static final String SIGNATURE_ALGORITHM_NAME = "SHA256withRSA";
	public static final String DKIM_SERIALIZATION_RELAXED_CODE = "relaxed";
	public static final String DKIM_SERIALIZATION_SIMPLE_CODE = "simple";

	private static final String SPECIAL_CHARS_REGEXP = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
	private static final String VALID_CHARS_REGEXP = "[^\\s" + SPECIAL_CHARS_REGEXP + "]";
	private static final String QUOTED_USER_REGEXP = "(\"[^\"]*\")";
	private static final String WORD_REGEXP = "((" + VALID_CHARS_REGEXP + "|')+|" + QUOTED_USER_REGEXP + ")";
	private static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";
	private static final String USER_REGEX = "^\\s*" + WORD_REGEXP + "(\\." + WORD_REGEXP + ")*$";
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);
	private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);
	private static final String DOMAIN_PART_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
	private static final String TOP_DOMAIN_PART_REGEX = "\\p{Alpha}{2,}";
	private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_PART_REGEX + "\\.)+" + "(" + TOP_DOMAIN_PART_REGEX + ")$";
	private static final Pattern DOMAIN_NAME_PATTERN = Pattern.compile(DOMAIN_NAME_REGEX);

	private static final Map<String, DomainKey> DOMAINKEY_CACHE = new HashMap<>();
	private static final Pattern RECORD_PATTERN = Pattern.compile("(?:\"(.*?)\"(?: |$))|(?:'(.*?)'(?: |$))|(?:(.*?)(?: |$))");
	private static final long DEFAULT_CACHE_TTL = 2 * 60 * 60 * 1000;
	private static long cacheTtl = DEFAULT_CACHE_TTL;

	public enum LineBreak {
		/**
		 * No linebreak
		 */
		Unknown(null),

		/**
		 * Multiple linebreak types
		 */
		Mixed(null),

		/**
		 * Unix/Linux linebreak ("\n")
		 */
		Unix("\n"),

		/**
		 * Mac/Apple linebreak ("\r")
		 */
		Mac("\r"),

		/**
		 * Windows linebreak ("\r\n")
		 */
		Windows("\r\n");

		private final String representationString;

		@Override
		public String toString() {
			return representationString;
		}

		LineBreak(final String representationString) {
			this.representationString = representationString;
		}

		public static LineBreak getLineBreakTypeByName(final String lineBreakTypeName) {
			if ("WINDOWS".equalsIgnoreCase(lineBreakTypeName)) {
				return LineBreak.Windows;
			} else if ("UNIX".equalsIgnoreCase(lineBreakTypeName)) {
				return LineBreak.Unix;
			} else if ("MAC".equalsIgnoreCase(lineBreakTypeName)) {
				return LineBreak.Mac;
			} else {
				return LineBreak.Unknown;
			}
		}
	}

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
		body = normalizeLineBreaks(body, LineBreak.Windows);

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
				if (isBlank(dkimSignatureVersion)) {
					throw new Exception("DKIM signature is missing the mandatory version(v) value");
				} else if (!"1".equals(dkimSignatureVersion)) {
					throw new Exception("DKIM signature has an unkown version(v) value: " + dkimSignatureVersion);
				}

				final String dkimSignatureAlgorithm = signatureValues.get("a");
				if (isBlank(dkimSignatureAlgorithm)) {
					throw new Exception("DKIM signature is missing the mandatory algorithm(a) value");
				} else if (!DkimUtilities.ALLOWED_DKIM_SIGNATURE_ALGORITHM_CODE.equalsIgnoreCase(dkimSignatureAlgorithm)) {
					throw new Exception("DKIM signature used an unsupported algorithm: " + dkimSignatureAlgorithm);
				}

				final String dkimSignatureDomain = signatureValues.get("d");
				if (isBlank(dkimSignatureDomain)) {
					throw new Exception("DKIM signature is missing the mandatory domain(d) value");
				}

				final String selector = signatureValues.get("s");
				if (isBlank(selector)) {
					throw new Exception("DKIM signature is missing the mandatory selector(s) value");
				}

				final String dkimSignatureBodyHash = signatureValues.get("bh");
				if (isBlank(dkimSignatureBodyHash)) {
					throw new Exception("DKIM signature is missing the mandatory bodyHash(bh) value");
				}

				final String headersIncludedInSignature = signatureValues.get("h");
				if (isBlank(headersIncludedInSignature)) {
					throw new Exception("DKIM signature is missing the mandatory headersIncludedInSignature(h) value");
				}

				final String dkimSignatureBytesBase64 = signatureValues.get("b");
				if (isBlank(dkimSignatureBytesBase64)) {
					throw new Exception("DKIM signature is missing the mandatory dkimSignatureBytes(b) value");
				}

				String returnPathDomain = null;
				try {
					returnPathDomain = getDomainFromEmail(returnPath);
				} catch (final Exception e) {
					throw new Exception("Return-Path header value '" + returnPath + "' is invalid: " + e.getMessage());
				}
				if (isBlank(returnPathDomain)) {
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
				if (isBlank(returnPathDomain)) {
					throw new Exception("Return-Path header value has no domain");
				}

				final String cononicalization = signatureValues.get("c");
				if (isBlank(cononicalization)) {
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
					canonicalBody = DkimUtilities.canonicalizeBody(useRelaxedBodyCanonicalization, streamToString(inputStream, StandardCharsets.UTF_8));
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
				final boolean result = signature.verify(Base64.getDecoder().decode(dkimSignatureBytesBase64.getBytes(StandardCharsets.UTF_8)));
				return result;
			}
		} catch (final Exception e) {
			e.printStackTrace();
			return false;
		}
	}

	public static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}

	public static String normalizeLineBreaks(final String value, final LineBreak type) {
		if (value == null) {
			return value;
		} else {
			final String returnString = value.replace(LineBreak.Windows.toString(), LineBreak.Unix.toString()).replace(LineBreak.Mac.toString(), LineBreak.Unix.toString());
			if (type == LineBreak.Mac) {
				return returnString.replace(LineBreak.Unix.toString(), LineBreak.Mac.toString());
			} else if (type == LineBreak.Windows) {
				return returnString.replace(LineBreak.Unix.toString(), LineBreak.Windows.toString());
			} else {
				return returnString;
			}
		}
	}

	public static String streamToString(final InputStream inputStream, final Charset encoding) throws IOException {
		return new String(streamToByteArray(inputStream), encoding);
	}

	public static byte[] streamToByteArray(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			return null;
		} else {
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
				copy(inputStream, byteArrayOutputStream);
				return byteArrayOutputStream.toByteArray();
			}
		}
	}

	public static long copy(final InputStream inputStream, final OutputStream outputStream) throws IOException {
		final byte[] buffer = new byte[4096];
		int lengthRead = -1;
		long bytesCopied = 0;
		while ((lengthRead = inputStream.read(buffer)) > -1) {
			outputStream.write(buffer, 0, lengthRead);
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}

	public static long copy(final Reader inputReader, final OutputStream outputStream, final Charset encoding) throws IOException {
		final char[] buffer = new char[4096];
		int lengthRead = -1;
		long bytesCopied = 0;
		while ((lengthRead = inputReader.read(buffer)) > -1) {
			final String data = new String(buffer, 0, lengthRead);
			outputStream.write(data.getBytes(encoding));
			bytesCopied += lengthRead;
		}
		outputStream.flush();
		return bytesCopied;
	}

	public static byte hexToByte(final char char1, final char char2) {
		return (byte) ((Character.digit(char1, 16) << 4) + Character.digit(char2, 16));
	}

	public static String byteToHex(final byte data) {
		return String.format("%02X", data);
	}

	public static String getDomainFromEmail(final String emailAddress) throws Exception {
		final Matcher m = EMAIL_PATTERN.matcher(emailAddress);

		// Check, if email address matches outline structure
		if (!m.matches()) {
			throw new Exception("Invalid email address");
		}

		// Check if user-part is valid
		if (!isValidUser(m.group(1))) {
			throw new Exception("Invalid email address");
		}

		// Check if domain-part is valid
		if (!isValidDomain(m.group(2))) {
			throw new Exception("Invalid email address");
		}

		return m.group(2);
	}

	public static boolean isValidUser(final String user) {
		return USER_PATTERN.matcher(user).matches();
	}

	public static boolean isValidDomain(final String domain) {
		String asciiDomainName;
		try {
			asciiDomainName = java.net.IDN.toASCII(domain);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// invalid domain name like abc@.ch
			return false;
		}

		// Do not allow ".local" top level domain
		if (asciiDomainName.toLowerCase().endsWith(".local")) {
			return false;
		}

		return DOMAIN_NAME_PATTERN.matcher(asciiDomainName).matches();
	}
}
