package de.soderer.utilities.mail.dkim.utilities;

import java.sql.Timestamp;
import java.text.DateFormat;
import java.text.DateFormatSymbols;
import java.text.SimpleDateFormat;
import java.time.DayOfWeek;
import java.time.Duration;
import java.time.LocalDate;
import java.time.LocalDateTime;
import java.time.LocalTime;
import java.time.ZoneId;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;
import java.time.format.DateTimeFormatter;
import java.time.format.DateTimeParseException;
import java.time.format.ResolverStyle;
import java.util.Calendar;
import java.util.Date;
import java.util.GregorianCalendar;
import java.util.List;
import java.util.Locale;
import java.util.TimeZone;
import java.util.UUID;
import java.util.regex.Pattern;

import jakarta.mail.internet.InternetAddress;

public class DateUtilities {
	public static final String DD_MM_YYYY_HH_MM_SS = "dd.MM.yyyy HH:mm:ss";
	public static final String DD_MM_YYYY_HH_MM_SS_Z = "dd.MM.yyyy HH:mm:ss z";
	public static final String DD_MM_YYYY_HH_MM = "dd.MM.yyyy HH:mm";
	public static final String DD_MM_YYYY = "dd.MM.yyyy";
	public static final String DDMMYYYY = "ddMMyyyy";
	public static final String YYYYMMDD = "yyyyMMdd";
	public static final String HHMMSS = "HHmmss";
	public static final String YYYY_MM_DD = "yyyy-MM-dd";
	public static final String YYYY_MM_DD_HH_MM = "yyyy-MM-dd HH:mm";
	public static final String DD_MM_YYYY_HH_MM_SS_ForFileName = "dd_MM_yyyy_HH_mm_ss";
	public static final String YYYYMMDDHHMMSS = "yyyyMMddHHmmss";
	public static final String YYYYMMDDHHMMSSSSS = "yyyyMMddHHmmssSSS";
	public static final String YYYY_MM_DD_HHMMSS = "yyyy-MM-dd HH:mm:ss";
	public static final String YYYYMMDD_HHMMSS = "yyyyMMdd-HHmmss";
	public static final String HHMM = "HHmm";

	/** Date format for ISO 8601 */
	public static final String ISO_8601_DATE_FORMAT_NO_TIMEZONE = "yyyy-MM-dd";
	/** Date format for ISO 8601 */
	public static final String ISO_8601_DATE_FORMAT = "yyyy-MM-ddX";
	/** DateTime format for ISO 8601 */
	public static final String ISO_8601_DATETIME_FORMAT_NO_TIMEZONE = "yyyy-MM-dd'T'HH:mm:ss";
	/** DateTime format for ISO 8601 */
	public static final String ISO_8601_DATETIME_WITH_NANOS_FORMAT_NO_TIMEZONE = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSS";
	/** DateTime format for ISO 8601 */
	public static final String ISO_8601_DATETIME_FORMAT = "yyyy-MM-dd'T'HH:mm:ssX";
	/** DateTime format for ISO 8601 */
	public static final String ISO_8601_DATETIME_WITH_NANOS_FORMAT = "yyyy-MM-dd'T'HH:mm:ss.SSSSSSSSSX";

	/** ANSI SQL standard date time format */
	public static final String ANSI_SQL_DATETIME_FORMAT = "yyyy-MM-dd HH:mm:ss";

	/** ANSI SQL standard date format */
	public static final String ANSI_SQL_DATE_FORMAT = "yyyy-MM-dd";

	public static String getWeekdayNameShort(final GregorianCalendar date) {
		final int dayInt = date.get(Calendar.DAY_OF_WEEK);
		final String dayString = DateFormatSymbols.getInstance().getWeekdays()[dayInt];
		return dayString.substring(0, 2);
	}

	public static DayOfWeek getDayOfWeekByNamePart(String weekDayPartString) {
		if (Utilities.isBlank(weekDayPartString)) {
			return null;
		} else {
			weekDayPartString = weekDayPartString.toLowerCase().trim();
			for (final DayOfWeek dayOfWeek : DayOfWeek.values()) {
				if (dayOfWeek.name().toLowerCase().startsWith(weekDayPartString)) {
					return dayOfWeek;
				}
			}

			if (weekDayPartString.startsWith("so") || weekDayPartString.startsWith("su")) {
				return DayOfWeek.SUNDAY;
			} else if (weekDayPartString.startsWith("mo")) {
				return DayOfWeek.MONDAY;
			} else if (weekDayPartString.startsWith("di") || weekDayPartString.startsWith("tu")) {
				return DayOfWeek.TUESDAY;
			} else if (weekDayPartString.startsWith("mi") || weekDayPartString.startsWith("we")) {
				return DayOfWeek.WEDNESDAY;
			} else if (weekDayPartString.startsWith("do") || weekDayPartString.startsWith("th")) {
				return DayOfWeek.THURSDAY;
			} else if (weekDayPartString.startsWith("fr")) {
				return DayOfWeek.FRIDAY;
			} else if (weekDayPartString.startsWith("sa")) {
				return DayOfWeek.SATURDAY;
			} else {
				return null;
			}
		}
	}

	/**
	 * Format a timestamp (Nanos in .Net format)
	 *
	 * @param ts
	 *            a Timestamp
	 * @return a String in format 'yyyy-mm-dd HH:MM:SS.NNNNNN'
	 */
	public static String formatTimestamp_yyyyMMdd_HHmmssNNNNNN(final Timestamp ts) {
		String returnString = "";

		if (ts != null) {
			final String s = DateTimeFormatter.ofPattern(YYYY_MM_DD_HHMMSS).format(DateUtilities.getLocalDateForDate(ts));
			String nanosString = Integer.toString(ts.getNanos());

			if (nanosString.length() > 6) {
				nanosString = nanosString.substring(0, 6);
			} else {
				while (nanosString.length() < 6) {
					nanosString += "0";
				}
			}

			returnString = s + nanosString;
		}

		return returnString;
	}

	/**
	 * Format a timestampString from format "dd.MM.yyyy" or "dd-MM-yyyy" to "yyyy-MM-dd"
	 *
	 * @param ddMMyyyyString
	 * @return
	 */
	public static String convert_ddMMyyyy_to_yyyyMMdd(final String ddMMyyyyString) {
		return ddMMyyyyString.substring(6, 10) + "-" + ddMMyyyyString.substring(3, 5) + "-" + ddMMyyyyString.substring(0, 2);
	}

	/**
	 * Format a timestampString from format "yyyy-MM-dd" or "yyyy.MM.dd" to "dd.MM.yyyy"
	 *
	 * @param ddMMyyyyString
	 * @return
	 */
	public static String convert_yyyyMMdd_to_ddMMyyyy(final String yyyyMMddString) {
		return yyyyMMddString.substring(8, 10) + "." + yyyyMMddString.substring(5, 7) + "." + yyyyMMddString.substring(0, 4);
	}

	public static String replaceDatePatternInString(final String stringWithPattern, final LocalDateTime localDateTime) {
		String returnString = stringWithPattern;
		returnString = returnString.replace("[yyyy]", String.format("%04d", localDateTime.getYear()));
		returnString = returnString.replace("[YYYY]", String.format("%04d", localDateTime.getYear()));
		returnString = returnString.replace("[MM]", String.format("%02d", localDateTime.getMonthValue()));
		returnString = returnString.replace("[dd]", String.format("%02d", localDateTime.getDayOfMonth()));
		returnString = returnString.replace("[DD]", String.format("%02d", localDateTime.getDayOfMonth()));
		returnString = returnString.replace("[HH]", String.format("%02d", localDateTime.getHour()));
		returnString = returnString.replace("[hh]", String.format("%02d", localDateTime.getHour()));
		returnString = returnString.replace("[mm]", String.format("%02d", localDateTime.getMinute()));
		returnString = returnString.replace("[SS]", String.format("%02d", localDateTime.getSecond()));
		returnString = returnString.replace("[ss]", String.format("%02d", localDateTime.getSecond()));
		returnString = returnString.replace("\\[", "[");
		returnString = returnString.replace("\\]", "]");
		return returnString;
	}

	public static LocalDateTime calculateETA(final LocalDateTime start, final long itemsToDo, final long itemsDone) {
		if (start == null || itemsToDo <= 0 || itemsDone <= 0 || itemsToDo < itemsDone) {
			return null;
		} else {
			final LocalDateTime now = LocalDateTime.now();
			if (start.isAfter(now)) {
				return null;
			} else {
				final Duration durationSinceStartToNow = Duration.between(start, now);
				final Duration durationFromStartToEnd = Duration.ofSeconds(itemsToDo * durationSinceStartToNow.toSeconds() / itemsDone);
				return start.plus(durationFromStartToEnd);
			}
		}
	}

	public static String getShortHumanReadableTimespan(final Duration duration, final boolean showMillis, final boolean showLeadingZeros) {
		final StringBuilder returnValue = new StringBuilder();

		final long millis = duration.toMillisPart();
		final long seconds = duration.toSecondsPart();
		final long minutes = duration.toMinutesPart();
		final long hours = duration.toHoursPart();
		final long days = duration.toDays() % 7;
		final long weeks = duration.toDays() / 7 % 52;
		final long years = duration.toDays() / 7 / 52;

		if (millis != 0 && showMillis) {
			returnValue.insert(0, "ms");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%03d", millis));
			} else {
				returnValue.insert(0, millis);
			}
		}

		if (seconds != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "s");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%02d", seconds));
			} else {
				returnValue.insert(0, seconds);
			}
		}

		if (minutes != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "m");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%02d", minutes));
			} else {
				returnValue.insert(0, minutes);
			}
		}

		if (hours != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "h");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%02d", hours));
			} else {
				returnValue.insert(0, hours);
			}
		}

		if (days != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "d");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%02d", days));
			} else {
				returnValue.insert(0, days);
			}
		}

		if (weeks != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "w");
			if (showLeadingZeros) {
				returnValue.insert(0, String.format("%02d", weeks));
			} else {
				returnValue.insert(0, weeks);
			}
		}

		if (years != 0) {
			if (returnValue.length() > 0) {
				returnValue.insert(0, " ");
			}
			returnValue.insert(0, "y");
			returnValue.insert(0, years);
		}

		if (returnValue.length() > 0) {
			return returnValue.toString();
		} else if (!showMillis) {
			if (showLeadingZeros) {
				return "00s";
			} else {
				return "0s";
			}
		} else {
			if (showLeadingZeros) {
				return "000ms";
			} else {
				return "0ms";
			}
		}
	}

	/**
	 * Get the duration between two timestamps as a string
	 *
	 * @param startTime
	 * @param endTime
	 * @return
	 */
	public static String getDuration(final Calendar startTime, final Calendar endTime) {
		final int durationInMilliSeconds = (int) (endTime.getTimeInMillis() - startTime.getTimeInMillis());
		final int milliSecondsPart = durationInMilliSeconds % 1000;
		final int secondsPart = durationInMilliSeconds / 1000 % 60;
		final int minutesPart = durationInMilliSeconds / 1000 / 60 % 60;
		final int hoursPart = durationInMilliSeconds / 1000 / 60 / 60 % 24;
		final int days = durationInMilliSeconds / 1000 / 60 / 60 % 24;

		String returnString = milliSecondsPart + "ms";
		if (secondsPart > 0) {
			returnString = secondsPart + "s " + returnString;
		}
		if (minutesPart > 0) {
			returnString = minutesPart + "m " + returnString;
		}
		if (hoursPart > 0) {
			returnString = hoursPart + "h " + returnString;
		}
		if (days > 0) {
			returnString = days + "d " + returnString;
		}
		return returnString;
	}

	public static boolean checkTimeMatchesPattern(final String pattern, final LocalTime time) {
		final Pattern timePattern = Pattern.compile(pattern.replace("*", "."));
		final String timeString = DateTimeFormatter.ofPattern(HHMM).format(time);
		return timePattern.matcher(timeString).matches();
	}

	/**
	 * Remove the time part of a GregorianCalendar
	 *
	 * @param value
	 * @return
	 */
	public static GregorianCalendar getDayWithoutTime(final GregorianCalendar value) {
		return new GregorianCalendar(value.get(Calendar.YEAR), value.get(Calendar.MONTH), value.get(Calendar.DAY_OF_MONTH));
	}

	/**
	 * Check if a day is included in a list of days
	 *
	 * @param listOfDays
	 * @param day
	 * @return
	 */
	public static boolean dayListIncludes(final List<LocalDate> listOfDays, final LocalDate day) {
		for (final LocalDate listDay : listOfDays) {
			if (listDay.getDayOfYear() == day.getDayOfYear()) {
				return true;
			}
		}
		return false;
	}

	public static LocalDateTime parseUnknownDateFormat(final String value) throws Exception {
		try {
			return parseLocalDateTime(DD_MM_YYYY_HH_MM_SS, value);
		} catch (@SuppressWarnings("unused") final DateTimeParseException e1) {
			try {
				return parseLocalDateTime(DD_MM_YYYY_HH_MM, value);
			} catch (@SuppressWarnings("unused") final DateTimeParseException e2) {
				try {
					return parseLocalDateTime(DD_MM_YYYY, value);
				} catch (@SuppressWarnings("unused") final DateTimeParseException e3) {
					try {
						return parseLocalDateTime(YYYY_MM_DD_HH_MM, value);
					} catch (@SuppressWarnings("unused") final DateTimeParseException e4) {
						try {
							return parseLocalDateTime(YYYYMMDDHHMMSS, value);
						} catch (@SuppressWarnings("unused") final DateTimeParseException e5) {
							try {
								return parseLocalDateTime(DDMMYYYY, value);
							} catch (@SuppressWarnings("unused") final DateTimeParseException e6) {
								throw new Exception("Unknown date format");
							}
						}
					}
				}
			}
		}
	}

	@SuppressWarnings("deprecation")
	public static LocalDateTime getLocalDateTimeForDate(Date date) {
		if (date == null) {
			return null;
		} else {
			try {
				date = new Date(date.getTime());
				final long milliseconds = date.getTime();
				final long epochSeconds = milliseconds / 1000;
				final int nanoseconds = ((int) (milliseconds % 1000)) * 1000000;
				final LocalDateTime localDateTime = LocalDateTime.ofEpochSecond(epochSeconds, nanoseconds, ZoneOffset.ofTotalSeconds(date.getTimezoneOffset() * -60));
				return localDateTime;
			} catch (final Exception e) {
				e.printStackTrace();
				return null;
			}
		}
	}

	public static LocalDateTime getLocalDateTime(final Long millis) {
		if (millis == null) {
			return null;
		} else {
			try {
				final Date date = new Date(millis);
				final long milliseconds = date.getTime();
				final long epochSeconds = milliseconds / 1000;
				final int nanoseconds = ((int) (milliseconds % 1000)) * 1000000;
				@SuppressWarnings("deprecation")
				final LocalDateTime localDateTime = LocalDateTime.ofEpochSecond(epochSeconds, nanoseconds, ZoneOffset.ofTotalSeconds(date.getTimezoneOffset() * -60));
				return localDateTime;
			} catch (final Exception e) {
				e.printStackTrace();
				return null;
			}
		}
	}

	public static LocalDate getLocalDateForDate(final Date date) {
		// new Date(date.getTime()) to convert value of java.sql.Date
		return (new Date(date.getTime())).toInstant().atZone(ZoneId.systemDefault()).toLocalDate();
	}

	public static Date getDateForLocalDateTime(final LocalDateTime localDateTime) {
		return Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant());
	}

	public static java.sql.Timestamp getSqlTimestampForLocalDateTime(final LocalDateTime localDateTime) {
		return new java.sql.Timestamp(Date.from(localDateTime.atZone(ZoneId.systemDefault()).toInstant()).getTime());
	}

	public static Date getDateForLocalDate(final LocalDate localDate) {
		return Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant());
	}

	public static java.sql.Date getSqlDateForLocalDate(final LocalDate localDate) {
		return new java.sql.Date(Date.from(localDate.atStartOfDay().atZone(ZoneId.systemDefault()).toInstant()).getTime());
	}

	public static Date getDateForZonedDateTime(final ZonedDateTime zonedDateTime) {
		return Date.from(zonedDateTime.withZoneSameInstant(ZoneId.systemDefault()).toInstant());
	}

	/**
	 * Get the ordinal of occurence of the given weekdy in its month
	 * @param dayOfMonth
	 * @return
	 */
	public static int getNumberOfWeekdayInMonth(final int dayOfMonth) {
		final float ordinalFloat = dayOfMonth / 7.0f;
		final int ordinalInt = (int) Math.round(Math.ceil(ordinalFloat));
		return ordinalInt;
	}

	public static Date changeDateTimeZone(final Date date, TimeZone sourceTimeZone, TimeZone destinationTimeZone) {
		if (date == null) {
			return null;
		} else {
			if (sourceTimeZone == null) {
				sourceTimeZone = TimeZone.getDefault();
			}
			if (destinationTimeZone == null) {
				destinationTimeZone = TimeZone.getDefault();
			}
			if (sourceTimeZone.equals(destinationTimeZone)) {
				return date;
			} else {
				long fromTZDst = 0;
				if (sourceTimeZone.inDaylightTime(date)) {
					fromTZDst = sourceTimeZone.getDSTSavings();
				}

				final long fromTZOffset = sourceTimeZone.getRawOffset() + fromTZDst;

				long toTZDst = 0;
				if (destinationTimeZone.inDaylightTime(date)) {
					toTZDst = destinationTimeZone.getDSTSavings();
				}
				final long toTZOffset = destinationTimeZone.getRawOffset() + toTZDst;

				return new Date(date.getTime() + (toTZOffset - fromTZOffset));
			}
		}
	}

	public static Date changeDateTimeZone(final Date date, ZoneId sourceZoneId, ZoneId destinationZoneId) {
		if (date == null) {
			return null;
		} else {
			if (sourceZoneId == null) {
				sourceZoneId = ZoneId.systemDefault();
			}
			if (destinationZoneId == null) {
				destinationZoneId = ZoneId.systemDefault();
			}
			if (sourceZoneId.equals(destinationZoneId)) {
				return date;
			} else {
				final LocalDateTime localDateTime = getLocalDateTimeForDate(date);
				final ZonedDateTime sourceZonedDateTime = localDateTime.atZone(sourceZoneId);
				final ZonedDateTime destinationZonedDateTime = sourceZonedDateTime.withZoneSameInstant(destinationZoneId);
				final Date rezonedDate = new Date(destinationZonedDateTime.withZoneSameLocal(ZoneId.systemDefault()).toInstant().toEpochMilli());
				return rezonedDate;
			}
		}
	}

	public static LocalDateTime changeDateTimeZone(final LocalDateTime localDateTime, ZoneId sourceZoneId, ZoneId destinationZoneId) {
		if (localDateTime == null) {
			return null;
		} else {
			if (sourceZoneId == null) {
				sourceZoneId = ZoneId.systemDefault();
			}
			if (destinationZoneId == null) {
				destinationZoneId = ZoneId.systemDefault();
			}
			if (sourceZoneId.equals(destinationZoneId)) {
				return localDateTime;
			} else {
				final ZonedDateTime sourceZonedDateTime = localDateTime.atZone(sourceZoneId);
				return sourceZonedDateTime.withZoneSameInstant(destinationZoneId).toLocalDateTime();
			}
		}
	}

	public static ZonedDateTime changeDateTimeZone(final ZonedDateTime zonedDateTime, ZoneId destinationZoneId) {
		if (zonedDateTime == null) {
			return null;
		} else {
			if (destinationZoneId == null) {
				destinationZoneId = ZoneId.systemDefault();
			}
			if (zonedDateTime.getZone().equals(destinationZoneId)) {
				return zonedDateTime;
			} else {
				return zonedDateTime.withZoneSameInstant(destinationZoneId);
			}
		}
	}

	public static DateTimeFormatter getDateFormatter(final Locale locale) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateFormatPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		return dateTimeFormatter;
	}

	public static DateTimeFormatter getDateFormatter(final Locale locale, final ZoneId zoneId) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateFormatPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		dateTimeFormatter.withZone(zoneId);
		return dateTimeFormatter;
	}

	public static String getDateFormatPattern(final Locale locale) {
		final SimpleDateFormat dateTimeFormat = (SimpleDateFormat) DateFormat.getDateInstance(DateFormat.SHORT, locale);
		return dateTimeFormat.toPattern().replaceFirst("y+", "yyyy");
	}

	public static String getDateTimeFormatPattern(final Locale locale) {
		return getDateFormatPattern(locale) + " HH:mm";
	}

	public static String getDateTimeFormatWithSecondsPattern(final Locale locale) {
		return getDateFormatPattern(locale) + " HH:mm:ss";
	}

	public static DateTimeFormatter getDateTimeFormatter(final Locale locale) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateTimeFormatPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		return dateTimeFormatter;
	}

	public static DateTimeFormatter getDateTimeFormatter(final Locale locale, final ZoneId zoneId) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateTimeFormatPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		dateTimeFormatter.withZone(zoneId);
		return dateTimeFormatter;
	}

	public static DateTimeFormatter getDateTimeFormatterWithSeconds(final Locale locale) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateTimeFormatWithSecondsPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		return dateTimeFormatter;
	}

	public static DateTimeFormatter getDateTimeFormatterWithSeconds(final Locale locale, final ZoneId zoneId) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(getDateTimeFormatPattern(locale));
		dateTimeFormatter.withResolverStyle(ResolverStyle.STRICT);
		dateTimeFormatter.withZone(zoneId);
		return dateTimeFormatter;
	}

	public static String formatDate(final String format, final ZonedDateTime date) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).format(date);
		}
	}

	public static String formatDate(final String format, final Date date) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).format(getLocalDateTimeForDate(date));
		}
	}

	public static String formatDate(final String format, final LocalDateTime date) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).format(date);
		}
	}

	public static String formatDate(final String format, final LocalDate date) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).format(date);
		}
	}

	public static String formatDate(final String format, final Date date, final Locale locale, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).localizedBy(locale).withZone(zoneId).format(getLocalDateTimeForDate(date));
		}
	}

	public static String formatDate(final String format, final LocalDateTime date, final Locale locale, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).localizedBy(locale).withZone(zoneId).format(date);
		}
	}

	public static String formatDate(final String format, final LocalDate date, final Locale locale, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).localizedBy(locale).withZone(zoneId).format(date);
		}
	}

	public static String formatDate(final String format, final Date date, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).withZone(zoneId).format(getLocalDateTimeForDate(date));
		}
	}

	public static String formatDate(final String format, final LocalDateTime date, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).withZone(zoneId).format(date);
		}
	}

	public static String formatDate(final String format, final ZonedDateTime date, final ZoneId zoneId) {
		if (date == null) {
			return null;
		} else {
			return DateTimeFormatter.ofPattern(format).withZone(zoneId).format(date);
		}
	}

	public static LocalDate parseLocalDate(final String dateFormatPattern, final String dateString) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(dateFormatPattern);
		final LocalDate localDate = LocalDate.parse(dateString, dateTimeFormatter);
		return localDate;
	}

	public static LocalDateTime parseLocalDateTime(final String dateTimeFormatPattern, final String dateTimeString) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(dateTimeFormatPattern);
		final LocalDateTime localDateTime = LocalDateTime.parse(dateTimeString, dateTimeFormatter);
		return localDateTime;
	}

	public static Date parseDateTime(final String format, final String dateTimeString) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(format);
		final LocalDateTime localDateTime = LocalDateTime.parse(dateTimeString, dateTimeFormatter);
		return getDateForLocalDateTime(localDateTime);
	}

	public static Date parseDateTime(final String format, final String dateTimeString, final TimeZone timeZone) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(format);
		dateTimeFormatter.withZone(timeZone.toZoneId());
		final LocalDateTime localDateTime = LocalDateTime.parse(dateTimeString, dateTimeFormatter);
		return getDateForLocalDateTime(localDateTime);
	}

	public static Date parseDateTime(final String format, final String dateTimeString, final ZoneId zoneId) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(format);
		dateTimeFormatter.withZone(zoneId);
		final LocalDateTime localDateTime = LocalDateTime.parse(dateTimeString, dateTimeFormatter);
		return getDateForLocalDateTime(localDateTime);
	}

	public static ZonedDateTime parseZonedDateTime(final String format, final String dateTimeString, final ZoneId zoneId) {
		final DateTimeFormatter dateTimeFormatter = DateTimeFormatter.ofPattern(format);
		dateTimeFormatter.withZone(zoneId);
		final ZonedDateTime zonedDateTime = ZonedDateTime.parse(dateTimeString, dateTimeFormatter);
		return zonedDateTime;
	}

	/**
	 * OpenJDK 15+ doesn't recognize german three letter months by "MMM" in SimpleDateFormat anymore.
	 * So here is a helper to cope with that problem.
	 */
	public static int parseThreeLetterMonth(final String threeLetterMonth) throws Exception {
		switch(threeLetterMonth.toUpperCase()) {
			case "JAN":
				return 1;
			case "FEB":
				return 2;
			case "MAR":
			case "MÄR":
				return 3;
			case "APR":
				return 4;
			case "MAY":
			case "MAI":
				return 5;
			case "JUN":
				return 6;
			case "JUL":
				return 7;
			case "AUG":
				return 8;
			case "SEP":
				return 9;
			case "OCT":
			case "OKT":
				return 10;
			case "NOV":
				return 11;
			case "DEC":
			case "DEZ":
				return 12;
			default:
				throw new Exception("Unknown three letter month: " + threeLetterMonth);
		}
	}

	public static String createICalEventInvitation(final String shortname, final String description, final ZonedDateTime startDateTime, final ZonedDateTime endDateTime, final String location, final InternetAddress organizer, final List<InternetAddress> participants) {
		String returnValue =
				"BEGIN:VCALENDAR\n";
		returnValue += "METHOD:REQUEST" + "\n";
		returnValue += "VERSION:2.0" + "\n";

		returnValue += "BEGIN:VEVENT" + "\n";

		returnValue += "DTSTAMP;VALUE=DATE-TIME:" + DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").format(ZonedDateTime.now().withZoneSameInstant(ZoneOffset.UTC)) + "\n";
		returnValue += "UID:" + UUID.randomUUID().toString().toUpperCase() + "\n";

		returnValue += "DTSTART;VALUE=DATE-TIME:" + DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").format(startDateTime.withZoneSameInstant(ZoneOffset.UTC)) + "\n";

		if (endDateTime != null) {
			returnValue += "DTEND;VALUE=DATE-TIME:" + DateTimeFormatter.ofPattern("yyyyMMdd'T'HHmmss'Z'").format(endDateTime.withZoneSameInstant(ZoneOffset.UTC)) + "\n";
		}

		if (location != null) {
			returnValue += "LOCATION;VALUE=TEXT:" + location + "\n";
		}

		returnValue += "SUMMARY;VALUE=TEXT:" + shortname + "\n";

		if (description != null) {
			returnValue += "DESCRIPTION;VALUE=TEXT:" + description + "\n";
		}

		if (organizer != null) {
			if (organizer.getPersonal() != null) {
				returnValue += "ORGANIZER;CN=" + organizer.getPersonal() + ":MAILTO:" + organizer.getAddress() + "\n";
			} else {
				returnValue += "ORGANIZER:MAILTO:" + organizer.getAddress() + "\n";
			}
		}

		if (participants != null) {
			for (final InternetAddress participant : participants) {
				if (participant.getPersonal() != null) {
					returnValue += "ATTENDEE;ROLE=REQ-PARTICIPANT;CN=" + participant.getPersonal() + ":MAILTO:" + participant.getAddress() + "\n";
				} else {
					returnValue += "ATTENDEE;ROLE=REQ-PARTICIPANT:MAILTO:" + participant.getAddress() + "\n";
				}
			}
		}

		returnValue += "END:VEVENT" + "\n";

		returnValue += "END:VCALENDAR\n";

		return returnValue;
	}
}
