package de.soderer.utilities.mail.dkim;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Result of the verification of all DKIM signatures of a message.
 * <p>
 * As defined in RFC 6376, invalid signatures do not make a message invalid: the message is valid, if at least one signature is valid and matches the required domain.
 */
public final class DkimVerificationResult {
	/**
	 * Results of the single signatures in order of appearance
	 */
	private final List<DkimSignatureResult> signatureResults;

	/**
	 * Creates a result.
	 *
	 * @param signatureResults results of the single signatures in order of appearance
	 */
	DkimVerificationResult(final List<DkimSignatureResult> signatureResults) {
		this.signatureResults = Collections.unmodifiableList(new ArrayList<>(signatureResults));
	}

	/**
	 * Returns whether the message has at least one DKIM signature.
	 *
	 * @return true for a signed message
	 */
	public boolean isSigned() {
		return !signatureResults.isEmpty();
	}

	/**
	 * Returns whether at least one signature is valid and matches the required domain.
	 *
	 * @return true for a validly signed message
	 */
	public boolean isValid() {
		return signatureResults.stream().anyMatch(DkimSignatureResult::isAligned);
	}

	/**
	 * Returns the results of the single signatures.
	 *
	 * @return unmodifiable list of the results in order of appearance
	 */
	public List<DkimSignatureResult> getSignatureResults() {
		return signatureResults;
	}

	/**
	 * Returns the signing domains of all valid signatures, which match the required domain.
	 *
	 * @return the signing domains, empty if there is no valid matching signature
	 */
	public List<String> getValidDomains() {
		return signatureResults.stream().filter(DkimSignatureResult::isAligned).map(DkimSignatureResult::getDomain).distinct().collect(Collectors.toList());
	}

	/**
	 * Returns the reasons of all failed signatures.
	 *
	 * @return the reasons separated by line breaks, or a note, if the message has no signature
	 */
	public String getErrorMessage() {
		if (signatureResults.isEmpty()) {
			return "Message has no DKIM signature";
		} else {
			return signatureResults.stream().filter(result -> !result.isAligned()).map(DkimSignatureResult::toString).collect(Collectors.joining("\n"));
		}
	}

	@Override
	public String toString() {
		return (isSigned() ? (isValid() ? "Valid" : "Invalid") : "Unsigned") + " " + signatureResults;
	}
}
