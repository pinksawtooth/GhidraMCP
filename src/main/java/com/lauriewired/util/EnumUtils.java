package com.lauriewired.util;

/**
 * Utility class for handling enums and their values.
 * This class provides a representation of an enum value with its name,
 * value, and comment.
 */
public final class EnumUtils {
	/**
	 * Represents a value of an enum.
	 */
	public static class EnumValue {
		/**
		 * The name of the enum value.
		 */
		public String name;

		/**
		 * The numeric value of the enum entry.
		 */
		public double value = 0; // Use double to handle GSON parsing number as double

		/**
		 * The comment for the enum value.
		 */
		public String comment;
	}
}