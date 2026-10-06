package de.soderer.utilities.mail.dkim.utilities;

/**
 * String helper methods.
 */
public class Utilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private Utilities() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Checks for a null, empty or whitespace only string.
	 *
	 * @param value the string
	 * @return true for null, empty or whitespace only
	 */
	public static boolean isBlank(final String value) {
		return value == null || value.length() == 0 || value.trim().length() == 0;
	}

	/**
	 * Checks for a string with at least one non whitespace character.
	 *
	 * @param value the string
	 * @return true for a string with non whitespace content
	 */
	public static boolean isNotBlank(final String value) {
		return !isBlank(value);
	}
}
