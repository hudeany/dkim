package de.soderer.utilities;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.mail.internet.AddressException;
import javax.mail.internet.InternetAddress;

public class MailUtilities {
	private static final String SPECIAL_CHARS_REGEXP = "\\p{Cntrl}\\(\\)<>@,;:'\\\\\\\"\\.\\[\\]";
	private static final String VALID_CHARS_REGEXP = "[^\\s" + SPECIAL_CHARS_REGEXP + "]";
	private static final String QUOTED_USER_REGEXP = "(\"[^\"]*\")";
	private static final String WORD_REGEXP = "((" + VALID_CHARS_REGEXP + "|')+|" + QUOTED_USER_REGEXP + ")";

	private static final String DOMAIN_PART_REGEX = "\\p{Alnum}(?>[\\p{Alnum}-]*\\p{Alnum})*";
	private static final String TOP_DOMAIN_PART_REGEX = "\\p{Alpha}{2,}";
	private static final String DOMAIN_NAME_REGEX = "^(?:" + DOMAIN_PART_REGEX + "\\.)+" + "(" + TOP_DOMAIN_PART_REGEX + ")$";

	/**
	 * Regular expression for parsing email addresses.
	 *
	 * Taken from Apache Commons Validator.
	 * If this is not working, shame on Apache ;)
	 */
	private static final String EMAIL_REGEX = "^\\s*?(.+)@(.+?)\\s*$";

	private static final String USER_REGEX = "^\\s*" + WORD_REGEXP + "(\\." + WORD_REGEXP + ")*$";

	/** Regular expression pattern for parsing email addresses. */
	private static final Pattern EMAIL_PATTERN = Pattern.compile(EMAIL_REGEX);

	private static final Pattern USER_PATTERN = Pattern.compile(USER_REGEX);

	private static final Pattern DOMAIN_NAME_PATTERN = Pattern.compile(DOMAIN_NAME_REGEX);

	public static boolean isEmailValid(final String emailAddress) {
		final Matcher m = EMAIL_PATTERN.matcher(emailAddress);

		// Check, if email address matches outline structure
		if (!m.matches()) {
			return false;
		}

		// Check if user-part is valid
		if (!isValidUser(m.group(1))) {
			return false;
		}

		// Check if domain-part is valid
		if (!isValidDomain(m.group(2))) {
			return false;
		}

		return true;
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

	/**
	 * Check if a given e-mail address is valid.
	 * Notice that a {@code null} value is invalid address.
	 *
	 * @param email an e-mail address to check.
	 * @return {@code true} if address is valid or {@code false} otherwise.
	 */
	public static boolean isEmailValidAndNormalized(final String email) {
		return email != null && isEmailValid(email) && email.equals(normalizeEmail(email));
	}

	public static InternetAddress[] getEmailAddressesFromList(final String emailAddressesListString) throws Exception {
		if (Utilities.isBlank(emailAddressesListString)) {
			return new InternetAddress[0];
		} else {
			final List<InternetAddress> emailAddresses = new ArrayList<>();

			if (!emailAddressesListString.contains(">")) {
				for (final String emailAddressString : emailAddressesListString.split(";|,| ")) {
					if (Utilities.isNotBlank(emailAddressString)) {
						final String normalizedEmailAddressString = normalizeEmail(emailAddressString);
						if (MailUtilities.isEmailValid(normalizedEmailAddressString)) {
							try {
								final InternetAddress nextAddress = new InternetAddress(normalizedEmailAddressString);
								nextAddress.validate();
								emailAddresses.add(nextAddress);
							} catch (final AddressException e) {
								throw new Exception("Invalid emailaddress found: " + emailAddressString, e);
							}
						} else {
							throw new Exception("Invalid emailaddress found: " + emailAddressString);
						}
					}
				}
			} else {
				for (final String nameWithEmailAddressString : emailAddressesListString.split(";|,|>")) {
					if (Utilities.isNotBlank(nameWithEmailAddressString)) {
						String name;
						String normalizedEmailAddressString;
						if (nameWithEmailAddressString.contains("<")) {
							name = nameWithEmailAddressString.substring(0, nameWithEmailAddressString.indexOf("<")).trim();
							normalizedEmailAddressString = normalizeEmail(nameWithEmailAddressString.substring(nameWithEmailAddressString.indexOf("<") + 1).trim());
						} else {
							name = null;
							normalizedEmailAddressString = normalizeEmail(nameWithEmailAddressString);
						}

						if (MailUtilities.isEmailValid(normalizedEmailAddressString)) {
							try {
								final InternetAddress nextAddress;
								if (Utilities.isBlank(name)) {
									nextAddress = new InternetAddress(normalizedEmailAddressString);
								} else {
									nextAddress = new InternetAddress(normalizedEmailAddressString, name);
								}
								nextAddress.validate();
								emailAddresses.add(nextAddress);
							} catch (final AddressException e) {
								throw new Exception("Invalid emailaddress found: " + nameWithEmailAddressString, e);
							}
						} else {
							throw new Exception("Invalid emailaddress found: " + nameWithEmailAddressString);
						}
					}
				}
			}

			return emailAddresses.toArray(new InternetAddress[0]);
		}
	}

	/**
	 * Call lowercase and trim on email address. Watch out: apostrophe and other
	 * special characters !#$%&'*+-/=?^_`{|}~ are allowed in local parts of
	 * emailaddresses
	 *
	 * @param email
	 * @return
	 */
	public static String normalizeEmail(final String email) {
		if (Utilities.isBlank(email)) {
			return null;
		} else {
			return email.toLowerCase().trim();
		}
	}
}
