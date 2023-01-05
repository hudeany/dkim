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
import java.util.Base64;
import java.util.Collections;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.StringTokenizer;
import java.util.regex.Pattern;

import de.soderer.utilities.TextUtilities;
import de.soderer.utilities.Utilities;

public final class DomainKey {
	private static final String DKIM_VERSION = "DKIM1";
	private static final String EMAIL_SERVICE_TYPE = "email";

	private final long timestamp;
	private final Pattern granularity;
	private final PublicKey publicKey;
	private final Set<String> serviceTypes;
	private final Map<Character, String> tags;

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

		final String serviceTypesTagValue = getTagValue('s', "*");
		serviceTypes = getServiceTypes(serviceTypesTagValue);
		if (!(serviceTypes.contains("*") || serviceTypes.contains(EMAIL_SERVICE_TYPE))) {
			throw new Exception("Incompatible service type s=" + getTagValue('s') + ".");
		}

		final String publicKeyTagValue = getTagValue('p');
		if (Utilities.isBlank(publicKeyTagValue)) {
			throw new Exception("Mandatory dkim data for public key (p=) is missing or empty.");
		}
		publicKey = getPublicKey(publicKeyTagValue);
		if (null == publicKeyTagValue) {
			throw new Exception("Incompatible public key p=" + getTagValue('p') + ".");
		}
	}

	private static Set<String> getServiceTypes(final String serviceTypesTagValue) {
		final Set<String> serviceTypesSet = new HashSet<>();
		final StringTokenizer tokenizer = new StringTokenizer(serviceTypesTagValue, ":", false);
		while (tokenizer.hasMoreElements()) {
			serviceTypesSet.add(tokenizer.nextToken().trim());
		}
		return serviceTypesSet;
	}

	private String getTagValue(final char tag) {
		return getTagValue(tag, null);
	}

	private String getTagValue(final char tag, final String fallback) {
		final String tagValue = tags.get(tag);
		return null == tagValue ? fallback : tagValue;
	}

	private static PublicKey getPublicKey(final String publicKeyTagValue) throws Exception {
		return getRsaPublicKey(publicKeyTagValue);
	}

	private static RSAPublicKey getRsaPublicKey(final String publicKeyTagValue) throws Exception {
		try {
			final KeyFactory keyFactory = KeyFactory.getInstance("RSA");
			final X509EncodedKeySpec publicKeySpec = new X509EncodedKeySpec(
					Base64.getDecoder().decode(publicKeyTagValue));
			return (RSAPublicKey) keyFactory.generatePublic(publicKeySpec);
		} catch (final NoSuchAlgorithmException nsae) {
			throw new Exception("RSA algorithm not suported by JVM", nsae);
		} catch (final IllegalArgumentException e) {
			throw new Exception("The public key " + publicKeyTagValue + " couldn't be read.", e);
		} catch (final InvalidKeySpecException e) {
			throw new Exception("The public key " + publicKeyTagValue + " couldn't be decoded.", e);
		}
	}

	private static Pattern getGranularityPattern(final String granularityPattern) {
		final StringTokenizer tokenizer = new StringTokenizer(granularityPattern, "*", true);
		final StringBuffer pattern = new StringBuffer();
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

	public long getTimestamp() {
		return timestamp;
	}

	public Pattern getGranularity() {
		return granularity;
	}

	public Set<String> getServiceTypes() {
		return serviceTypes;
	}

	public PublicKey getPublicKey() {
		return publicKey;
	}

	/**
	 * Returns the tags, this DomainKey was constructed from
	 */
	public Map<Character, String> getTags() {
		return tags;
	}

	@Override
	public String toString() {
		return "DomainKey [timestamp=" + timestamp + ", tags=" + tags + "]";
	}

	/**
	 * Check DKIM key compatibility with given private key and identity
	 */
	public void check(final String identity, final PrivateKey privateKey) throws Exception {
		checkIdentity(identity);
		checkKeyCompatiblilty(privateKey);
	}

	private void checkIdentity(final String identity) throws Exception {
		if (null != identity && !identity.contains("@")) {
			throw new Exception("Invalid identity: " + identity);
		}
		final String localPart = null == identity ? "" : identity.substring(0, identity.indexOf('@'));
		if (!granularity.matcher(localPart).matches()) {
			throw new Exception("Incompatible identity for granularity " + getTagValue('g') + ": " + identity);
		}
	}

	private void checkKeyCompatiblilty(final PrivateKey privateKey) throws Exception {
		try {
			final Signature signingSignature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
			signingSignature.initSign(privateKey);
			signingSignature.update(TextUtilities.GERMAN_TEST_STRING.getBytes(StandardCharsets.UTF_8));
			final byte[] signatureBytes = signingSignature.sign();

			final Signature verifyingSignature = Signature.getInstance(DkimUtilities.SIGNATURE_ALGORITHM_NAME);
			verifyingSignature.initVerify(publicKey);
			verifyingSignature.update(TextUtilities.GERMAN_TEST_STRING.getBytes(StandardCharsets.UTF_8));

			if (!verifyingSignature.verify(signatureBytes)) {
				throw new Exception("Incompatible private key and public key");
			}
		} catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
			throw new Exception("Performing cryptography failed", e);
		}
	}
}
