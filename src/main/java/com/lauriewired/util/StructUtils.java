package com.lauriewired.util;

/**
 * Utility class for handling structures and their members.
 * This class provides a representation of a structure member with its name,
 * type, comment, and offset.
 */
public final class StructUtils {
	/**
	 * Represents a member of a structure.
	 */
	public static class StructMember {
		/**
		 * The name of the member.
		 */
		public String name;

		/**
		 * The type of the member.
		 */
		public String type;

		/**
		 * The comment for the member.
		 */
		public String comment;

		/**
		 * The offset of the member in the structure.
		 * Initialized to -1 to indicate that it has not been set.
		 */
		public double offset = -1; // Use double to handle GSON parsing number as double
	}
}
