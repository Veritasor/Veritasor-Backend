/**
 * Check if a string looks like it was randomly generated.
 * Uses heuristics like character distribution and patterns.
 *
 * @param str - The string to analyze
 * @returns True if the string appears random
 */
export function looksLikeRandomString(str: string): boolean {
  if (str.length < 8) return false;

  // Check for high ratio of consonants (typical of random strings)
  const consonants = (str.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
  const vowels = (str.match(/[aeiou]/gi) || []).length;

  if (vowels === 0 && consonants > 6) return true;

  // Random strings often have unusual character distribution
  const uniqueChars = new Set(str.toLowerCase()).size;
  if (str.length > 10 && uniqueChars / str.length > 0.8) return true;

  // Check for random-looking patterns like "xjkwq" or "qpzm"
  const consecutiveConsonants = str.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi);
  if (consecutiveConsonants && consecutiveConsonants.length > 0) return true;

  return false;
}

/**
 * Check for repeating patterns in a string that might indicate automation.
 *
 * @param str - The string to check
 * @returns True if repeating patterns are found
 */
export function hasRepeatingPattern(str: string): boolean {
  const lower = str.toLowerCase();

  // Check for repeated sequences like "abcabc" or "testtest"
  for (let len = 3; len <= Math.floor(str.length / 2); len++) {
    const pattern = lower.slice(0, len);
    const rest = lower.slice(len);
    if (rest.startsWith(pattern)) {
      return true;
    }
  }

  // Check for excessive character repetition
  const charCounts = new Map<string, number>();
  for (const char of lower) {
    charCounts.set(char, (charCounts.get(char) || 0) + 1);
  }

  for (const [, count] of charCounts) {
    if (count > str.length / 2) {
      return true;
    }
  }

  return false;
}

/**
 * Check for sequential characters in a string (e.g., "abc", "123", "cba").
 *
 * @param str - The string to check
 * @returns True if sequential characters are found
 */
export function hasSequentialChars(str: string): boolean {
  const lower = str.toLowerCase();

  for (let i = 0; i < lower.length - 2; i++) {
    const char1 = lower.charCodeAt(i);
    const char2 = lower.charCodeAt(i + 1);
    const char3 = lower.charCodeAt(i + 2);

    // Check for ascending sequence
    if (char2 === char1 + 1 && char3 === char2 + 1) {
      return true;
    }

    // Check for descending sequence
    if (char2 === char1 - 1 && char3 === char2 - 1) {
      return true;
    }
  }

  return false;
}

/**
 * Check for common keyboard patterns (e.g., "qwerty", "asdfgh").
 *
 * @param str - The string to check
 * @returns True if keyboard patterns are found
 */
export function hasKeyboardPattern(str: string): boolean {
  const lower = str.toLowerCase();

  const patterns = [
    "qwerty",
    "asdfgh",
    "zxcvbn",
    "qwertz", // German keyboard
    "azerty", // French keyboard
    "12345",
    "54321",
    "09876",
  ];

  for (const pattern of patterns) {
    if (
      lower.includes(pattern) ||
      lower.includes(pattern.split("").reverse().join(""))
    ) {
      return true;
    }
  }

  return false;
}
