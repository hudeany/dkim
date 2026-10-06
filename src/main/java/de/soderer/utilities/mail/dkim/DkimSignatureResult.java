package de.soderer.utilities.mail.dkim;

/**
 * Result of the verification of one DKIM signature of a message.
 */
public final class DkimSignatureResult {
	/**
	 * Signing domain (d=) or null, if the signature could not be parsed
	 */
	private final String domain;

	/**
	 * Key selector (s=) or null, if the signature could not be parsed
	 */
	private final String selector;

	/**
	 * Whether the signature is cryptographically valid
	 */
	private final boolean valid;

	/**
	 * Whether the signature is valid and its signing domain matches the required domain
	 */
	private final boolean aligned;

	/**
	 * Reason, why the signature is invalid or does not match the required domain, or null
	 */
	private final String errorMessage;

	/**
	 * Creates a result.
	 *
	 * @param domain signing domain (d=) or null
	 * @param selector key selector (s=) or null
	 * @param valid whether the signature is cryptographically valid
	 * @param aligned whether the signature is valid and its signing domain matches the required domain
	 * @param errorMessage reason of a failure or null
	 */
	DkimSignatureResult(final String domain, final String selector, final boolean valid, final boolean aligned, final String errorMessage) {
		this.domain = domain;
		this.selector = selector;
		this.valid = valid;
		this.aligned = aligned;
		this.errorMessage = errorMessage;
	}

	/**
	 * Returns the signing domain (d=).
	 *
	 * @return the signing domain or null, if the signature could not be parsed
	 */
	public String getDomain() {
		return domain;
	}

	/**
	 * Returns the key selector (s=).
	 *
	 * @return the key selector or null, if the signature could not be parsed
	 */
	public String getSelector() {
		return selector;
	}

	/**
	 * Returns whether the signature is cryptographically valid, independent of its signing domain.
	 *
	 * @return true for a valid signature
	 */
	public boolean isValid() {
		return valid;
	}

	/**
	 * Returns whether the signature is valid and its signing domain matches the required domain.
	 *
	 * @return true for a valid signature of the required domain
	 */
	public boolean isAligned() {
		return aligned;
	}

	/**
	 * Returns the reason, why the signature is invalid or does not match the required domain.
	 *
	 * @return the reason or null for a valid matching signature
	 */
	public String getErrorMessage() {
		return errorMessage;
	}

	@Override
	public String toString() {
		return "DKIM signature d=" + domain + " s=" + selector + ": " + (aligned ? "valid" : (valid ? "valid, but domain does not match: " : "invalid: ") + errorMessage);
	}
}
