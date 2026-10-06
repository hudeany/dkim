package de.soderer.utilities.mail.dkim;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import de.soderer.utilities.mail.dkim.utilities.Utilities;

/**
 * Public key record of a DKIM signing domain ("selector._domainkey.domain" TXT record, RFC 6376, section 3.6.1).
 */
public final class DomainKey {
	/**
	 * Supported key record version.
	 */
	private static final String DKIM_VERSION = "DKIM1";
	/**
	 * Service type for email.
	 */
	private static final String EMAIL_SERVICE_TYPE = "email";
	/**
	 * Data signed and verified to check the compatibility of a private key with this public key.
	 */
	private static final String TEST_DATA = "DKIM key compatibility check \u00e4\u00f6\u00fc\u00df";

	/**
	 * Time of creation in milliseconds, used for the cache time to live.
	 */
	private final long timestamp;
	/**
	 * Pattern of allowed local parts of the identity (g=, from the former DomainKeys specification).
	 */
	private final Pattern granularity;
	/**
	 * The public key (p=).
	 */
	private final PublicKey publicKey;
	/**
	 * Allowed service types (s=).
	 */
	private final Set<String> serviceTypes;
	/**
	 * All tags of the key record.
	 */
	private final Map<Character, String> tags;

	/**
	 * Creates a DomainKey from the tags of a key record and checks them.
	 *
	 * @param tags the tags by tag name
	 * @throws Exception for an incompatible version, key type, hash algorithm or service type, a missing, revoked (empty) or invalid public key
	 */
	public DomainKey(final Map<Character, String> tags) throws Exception {
		timestamp = System.currentTimeMillis();
		this.tags = Collections.unmodifiableMap(tags);

		final String dkimVersionTagValue = getTagValue('v', DKIM_VERSION);
		if (!(DKIM_VERSION.equals(dkimVersionTagValue))) {
			throw new Exception("Incompatible version v=" + getTagValue('v') + ".");
		}

		final String granularityTagValue = getTagValue('g', "*");
		granularity = getGranularityPattern(granularityTagValue);

		final String keyTypeTagValue = getTagValue('k', "rsa");
		if (!"rsa".equalsIgnoreCase(keyTypeTagValue)) {
			throw new Exception("Incompatible key type k=" + getTagValue('k') + ".");
		}

		// Acceptable hash algorithms (h=): if given, "sha256" must be included, because only rsa-sha256 is supported
		final String hashAlgorithmsTagValue = getTagValue('h');
		if (hashAlgorithmsTagValue != null && !Arrays.asList(hashAlgorithmsTagValue.replaceAll("\\s+", "").toLowerCase(Locale.ROOT).split(":")).contains("sha256")) {
			throw new Exception("Incompatible hash algorithms h=" + hashAlgorithmsTagValue + ".");
		}

		final String serviceTypesTagValue = getTagValue('s', "*");
		serviceTypes = getServiceTypes(serviceTypesTagValue);
		if (!(serviceTypes.contains("*") || serviceTypes.contains(EMAIL_SERVICE_TYPE))) {
			throw new Exception("Incompatible service type s=" + getTagValue('s') + ".");
		}

		final String publicKeyTagValue = getTagValue('p');
		if (publicKeyTagValue == null) {
			throw new Exception("Mandatory dkim data for public key (p=) is missing.");
		} else if (Utilities.isBlank(publicKeyTagValue)) {
			// RFC 6376: an empty value means that the key has been revoked
			throw new Exception("DKIM public key (p=) has been revoked.");
		}
		publicKey = getPublicKey(publicKeyTagValue);
		if (null == publicKey) {
			throw new Exception("Incompatible public key p=" + getTagValue('p') + ".");
		}
	}

	/**
	 * Parses the service types of the s= tag.
	 *
	 * @param serviceTypesTagValue colon separated service types
	 * @return the service types
	 */
	private static Set<String> getServiceTypes(final String serviceTypesTagValue) {
		final Set<String> serviceTypesSet = new HashSet<>();
		final StringTokenizer tokenizer = new StringTokenizer(serviceTypesTagValue, ":", false);
		while (tokenizer.hasMoreElements()) {
			serviceTypesSet.add(tokenizer.nextToken().trim());
		}
		return serviceTypesSet;
	}

	/**
	 * Returns the value of a tag.
	 *
	 * @param tag the tag name
	 * @return the value or null
	 */
	private String getTagValue(final char tag) {
		return getTagValue(tag, null);
	}

	/**
	 * Returns the value of a tag or a default value.
	 *
	 * @param tag the tag name
	 * @param fallback the default value
	 * @return the value or the default value, if the tag is missing
	 */
	private String getTagValue(final char tag, final String fallback) {
		final String tagValue = tags.get(tag);
		return null == tagValue ? fallback : tagValue;
	}

	/**
	 * Decodes the public key of the p= tag.
	 *
	 * @param publicKeyTagValue base64 encoded key data
	 * @return the public key
	 * @throws Exception if the key cannot be decoded
	 */
	private static PublicKey getPublicKey(final String publicKeyTagValue) throws Exception {
		return getRsaPublicKey(publicKeyTagValue);
	}

	/**
	 * Decodes an RSA public key (X.509 SubjectPublicKeyInfo, base64, whitespace allowed).
	 *
	 * @param publicKeyTagValue base64 encoded key data
	 * @return the RSA public key
	 * @throws Exception if the key cannot be decoded
	 */
	private static RSAPublicKey getRsaPublicKey(final String publicKeyTagValue) throws Exception {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			// The key data may contain whitespace, e.g. from splitting long DNS TXT records
			final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(Base64.getDecoder().decode(publicKeyTagValue.replaceAll("\\s+", "")));
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (final NoSuchAlgorithmException nsae) {
			throw new Exception("RSA algorithm not supported by JVM", nsae);
		} catch (final IllegalArgumentException e) {
			throw new Exception("The public key " + publicKeyTagValue + " couldn't be read.", e);
		} catch (final InvalidKeySpecException e) {
			throw new Exception("The public key " + publicKeyTagValue + " couldn't be decoded.", e);
		}
	}

	/**
	 * Converts a granularity value with "*" wildcards into a regular expression.
	 *
	 * @param granularityPattern the g= value
	 * @return the compiled pattern
	 */
	private static Pattern getGranularityPattern(final String granularityPattern) {
		final StringTokenizer tokenizer = new StringTokenizer(granularityPattern, "*", true);
		final StringBuilder pattern = new StringBuilder();
		while (tokenizer.hasMoreElements()) {
			final String token = tokenizer.nextToken();
			if ("*".equals(token)) {
				pattern.append(".*");
			} else {
				pattern.append(Pattern.quote(token));
			}
		}
		return Pattern.compile(pattern.toString());
	}

	/**
	 * Returns the time of creation of this object.
	 *
	 * @return the time in milliseconds
	 */
	public long getTimestamp() {
		return timestamp;
	}

	/**
	 * Returns the pattern of allowed local parts of the identity (g=).
	 *
	 * @return the granularity pattern
	 */
	public Pattern getGranularity() {
		return granularity;
	}

	/**
	 * Returns the allowed service types (s=).
	 *
	 * @return the service types
	 */
	public Set<String> getServiceTypes() {
		return serviceTypes;
	}

	/**
	 * Returns the public key (p=).
	 *
	 * @return the public key
	 */
	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the tags, this DomainKey was created from.
	 *
	 * @return the unmodifiable tags by tag name
	 */
	public Map<Character, String> getTags() {
		return tags;
	}

	@Override
	public String toString() {
		return "DomainKey [timestamp=" + timestamp + ", tags=" + tags + "]";
	}

	/**
	 * Checks that a private key and identity can be used with this DomainKey, e.g. before signing messages.
	 *
	 * @param identity the signing identity or null
	 * @param privateKey the private key
	 * @throws Exception if the identity does not match the granularity or the private key does not match the public key
	 */
	public void check(final String identity, final PrivateKey privateKey) throws Exception {
		checkIdentity(identity);
		checkKeyCompatibility(privateKey);
	}

	/**
	 * Checks the local part of an identity against the granularity pattern.
	 *
	 * @param identity the identity or null
	 * @throws Exception if the identity is invalid or not allowed
	 */
	private void checkIdentity(final String identity) throws Exception {
		if (null != identity && !identity.contains("@")) {
			throw new Exception("Invalid identity: " + identity);
		}
		final String localPart = null == identity ? "" : identity.substring(0, identity.indexOf('@'));
		if (!granularity.matcher(localPart).matches()) {
			throw new Exception("Incompatible identity for granularity " + getTagValue('g') + ": " + identity);
		}
	}

	/**
	 * Checks that a private key matches the public key by signing and verifying test data.
	 *
	 * @param privateKey the private key
	 * @throws Exception if the keys do not match
	 */
	private void checkKeyCompatibility(final PrivateKey privateKey) throws Exception {
		try {
			final Signature signingSignature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
			signingSignature.initSign(privateKey);
			signingSignature.update(TEST_DATA.getBytes(StandardCharsets.UTF_8));
			final byte[] signatureBytes = signingSignature.sign();

			final Signature verifyingSignature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
			verifyingSignature.initVerify(publicKey);
			verifyingSignature.update(TEST_DATA.getBytes(StandardCharsets.UTF_8));

			if (!verifyingSignature.verify(signatureBytes)) {
				throw new Exception("Incompatible private key and public key");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new Exception("Performing cryptography failed", e);
		}
	}
}
