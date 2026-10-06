package de.soderer.utilities.mail.dkim.utilities;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Email address helper methods.
 */
public class MailUtilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private MailUtilities() {
		throw new IllegalStateException("Utility class");
	}

	/**
	 * Special characters, which are not allowed unquoted in the local part.
	 */
	private static final String SPECIAL_CHARS_REGEXP = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
	/**
	 * Characters allowed unquoted in the local part.
	 */
	private static final String VALID_CHARS_REGEXP = "[^\\s" + SPECIAL_CHARS_REGEXP + "]";
	/**
	 * Quoted local part.
	 */
	private static final String QUOTED_USER_REGEXP = "(\"[^\"]*\")";
	/**
	 * One word of the local part.
	 */
	private static final String WORD_REGEXP = "((" + VALID_CHARS_REGEXP + "|')+|" + QUOTED_USER_REGEXP + ")";

	/**
	 * One label of a domain name.
	 */
	private static final String DOMAIN_PART_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
	// Alphabetic top level domain or internationalized top level domain in punycode (e.g. "xn--p1ai")
	/**
	 * Top level domain: alphabetic or internationalized in punycode (e.g. "xn--p1ai").
	 */
	private static final String TOP_DOMAIN_PART_REGEX = "(?:\\p{Alpha}{2,}|xn--[\\p{Alnum}-]+)";
	/**
	 * Complete domain name with at least two labels.
	 */
	private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_PART_REGEX + "\\.)+" + "(" + TOP_DOMAIN_PART_REGEX + ")$";

	/**
	 * Regular expression to split an email address into local part and domain. Taken from Apache Commons Validator.
	 */
	private static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";

	/**
	 * Regular expression of a valid local part.
	 */
	private static final String USER_REGEX = "^\\s*" + WORD_REGEXP + "(\\." + WORD_REGEXP + ")*$";

	/**
	 * Pattern to split an email address into local part and domain.
	 */
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

	/**
	 * Pattern of a valid local part.
	 */
	private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);

	/**
	 * Pattern of a valid domain name.
	 */
	private static final Pattern DOMAIN_NAME_PATTERN = Pattern.compile(DOMAIN_NAME_REGEX);

	/**
	 * Returns the domain of a valid email address.
	 *
	 * @param emailAddress the email address
	 * @return the domain part
	 * @throws Exception if the email address is invalid
	 */
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

	/**
	 * Checks the local part of an email address.
	 *
	 * @param user the local part
	 * @return true for a valid local part
	 */
	public static boolean isValidUser(final String user) {
		return USER_PATTERN.matcher(user).matches();
	}

	/**
	 * Checks a domain name. Internationalized domain names are converted to punycode first, the top level domain ".local" is not allowed.
	 *
	 * @param domain the domain name
	 * @return true for a valid domain name
	 */
	public static boolean isValidDomain(final String domain) {
		String asciiDomainName;
		try {
			asciiDomainName = java.net.IDN.toASCII(domain);
		} catch (@SuppressWarnings("unused") final Exception e) {
			// invalid domain name like abc@.ch
			return false;
		}

		// Do not allow ".local" top level domain
		if (asciiDomainName.toLowerCase(java.util.Locale.ROOT).endsWith(".local")) {
			return false;
		}

		return DOMAIN_NAME_PATTERN.matcher(asciiDomainName).matches();
	}

}
