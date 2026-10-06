package de.soderer.utilities.mail.dkim.utilities;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

/**
 * Stream helper methods.
 */
public class IoUtilities {
	/**
	 * Utility class, not to be instantiated.
	 */
	private IoUtilities() {
		throw new IllegalStateException("Utility class");
	}


	/**
	 * Reads all remaining data of a stream.
	 *
	 * @param inputStream the stream
	 * @return the data or null for a null stream
	 * @throws IOException if reading fails
	 */
	public static byte[] toByteArray(final InputStream inputStream) throws IOException {
		if (inputStream == null) {
			return null;
		} else {
			try (ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream()) {
				copy(inputStream, byteArrayOutputStream);
				return byteArrayOutputStream.toByteArray();
			}
		}
	}

	/**
	 * Copies all remaining data of a stream into another stream.
	 *
	 * @param inputStream source stream
	 * @param outputStream destination stream
	 * @return number of copied bytes
	 * @throws IOException if reading or writing fails
	 */
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

}
