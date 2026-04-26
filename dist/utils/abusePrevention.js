/**
 * Abuse Prevention Utilities for Signup
 *
 * This module provides heuristics and validation functions to prevent
 * automated abuse of the signup endpoint, including:
 * - Disposable email domain detection
 * - Password strength validation
 * - Email pattern analysis
 * - Suspicious activity scoring
 *
 * @module abusePrevention
 */
/**
 * List of known disposable/temporary email domains.
 * These domains are commonly used for creating throwaway accounts.
 * Source: Curated from various disposable email provider lists.
 */
const DISPOSABLE_EMAIL_DOMAINS = new Set([
    // 10 Minute Mail variants
    "10minutemail.com",
    "10minutemail.net",
    "10minutemail.org",
    "10minute-mail.com",
    // Temp Mail variants
    "tempmail.com",
    "temp-mail.org",
    "temp-mail.com",
    "temporary-mail.org",
    // Guerrilla Mail
    "guerrillamail.com",
    "guerrillamail.org",
    "guerrillamail.net",
    "guerrillamail.info",
    // Mailinator
    "mailinator.com",
    "mailinator.net",
    "mailinator.org",
    // Throwaway
    "throwaway.email",
    "throwawaymail.com",
    "throwawaymail.org",
    // Fake Inbox
    "fakeinbox.com",
    "fakeinbox.org",
    // Maildrop
    "maildrop.cc",
    "maildrop.org",
    // Getairmail
    "getairmail.com",
    "getairmail.org",
    // YOPmail
    "yopmail.com",
    "yopmail.fr",
    "yopmail.net",
    // EmailOnDeck
    "emailondeck.com",
    // Spam-related
    "spambox.us",
    "spamfree24.org",
    "spamfree24.com",
    // Other common disposables
    "dispostable.com",
    "mailnesia.com",
    "mintemail.com",
    "mohmal.com",
    "mytemp.email",
    "mytempemail.com",
    "tempail.com",
    "tempinbox.com",
    "tempm.com",
    "tempmailer.com",
    "trashmail.com",
    "trashmail.org",
    "trashmail.net",
    "guerrillamailblock.com",
    "pokemail.net",
    "sharklasers.com",
    "grr.la",
    "guerrillamail.de",
    "guerrillamail.es",
    "guerrillamail.eu",
    // Additional common domains
    "mail.com", // Has free tier often abused
    "email.com",
    "mail.org",
    // Recent additions
    "bumpymail.com",
    "cashflow35.com",
    "crossover.net",
    "deadaddress.com",
    "docfiles.org",
    "drivetagdev.com",
    "dropcake.de",
    "dropmail.me",
    "duck2.club",
    "e-mail.com",
    "e-mail.org",
    "email.net",
    "emailfake.com",
    "emailsensei.com",
    "emailfake.net",
    "emailfreedom.com",
    "emailgenerator.de",
    "emailgo.de",
    "emailizable.com",
    "emailmenow.info",
    "emailproxsy.com",
    "emailsingularity.net",
    "emailtech.info",
    "emailtemporanea.com",
    "emailtemporar.ro",
    "emailtmp.com",
    "emailure.net",
    "emailzombie.com",
    "emz.net",
    "enterto.com",
    "ephemail.net",
    "etranquil.com",
    "etranquil.net",
    "etranquil.org",
    "evopo.com",
    "explodemail.com",
    "express.net.ua",
    "extreme14.com",
    "fake-email.com",
    "fake-mail.com",
    "fakedemail.com",
    "fakeinbox.info",
    "fakemail.fr",
    "fakemailgenerator.com",
    "fakemailz.com",
    "fallinhay.com",
    "fantasymail.de",
    "fast-mail.org",
    "fastacuras.com",
    "fastchevy.com",
    "fastchrysler.com",
    "fastkawasaki.com",
    "fastmazda.com",
    "fastmitsubishi.com",
    "fastnissan.com",
    "fastsubaru.com",
    "fastsuzuki.com",
    "fasttoyota.com",
    "fastyamaha.com",
    "fatflap.com",
    "fdfdsfds.com",
    "fightallspam.com",
    "fiifke.de",
    "filbert4u.com",
    "filberts4u.com",
    "flowu.com",
    "footard.com",
    "forecastertests.com",
    "forgetmail.com",
    "fornow.eu",
    "forspam.net",
    "foxja.com",
    "foxtrotter.info",
    "free-email.to",
    "free-mail.cc",
    "free-mail.com",
    "freealt.net",
    "freebullets.com",
    "freecat.net",
    "freedom4you.net",
    "freefattymovies.com",
    "freehotmail.net",
    "freeinbox.email",
    "freelance-france.eu",
    "freemail1997.com",
    "freemailhq.com",
    "freeplumpervideos.com",
    "freemail.org",
    "freeschool.org",
    "freeshipping.org",
    "freeteek.com",
    "freezepea.com",
    "freundin.ru",
    "front14.org",
    "ftp.sh",
    "ftpaccess.cc",
    "ftpinc.ca",
    "fuckedcompany.com",
    "fullangle.org",
    "fullmarkz.com",
    "funnycollection.com",
    "funnycrap.com",
    "furz.com",
    "fxnxs.com",
    "fyii.de",
    "g.hmail.us",
    "g4hdrop.us",
    "gafy.net",
    "galaxy.tv",
    "gally.jp",
    "gamail.com",
    "game.com",
    "gamequeer.com",
    "gamg.ru",
    "garasikomputer.com",
    "garbage.com",
    "garbagemail.org",
    "garliclife.com",
    "garrifulio.mailexpire.com",
    "garrymoo.org",
    "gav0.com",
    "gbcmail.win",
    "gcmail.org",
    "gdmail.top",
    "gedmail.win",
    "geezmail.ga",
    "gegeweb.com",
    "geldwaschmaschine.de",
    "gelitik.in",
    "gen.uu.gl",
    "genmail.gen.in",
    "geronra.com",
    "geschent.biz",
    "get-mail.org",
    "get.pp.ua",
    "get1mail.com",
    "get2mail.fr",
    "getairmail.cf",
    "getairmail.ga",
    "getairmail.gq",
    "getairmail.ml",
    "getairmail.tk",
    "geteit.com",
    "getfun.men",
    "getmails.eu",
    "getnanny.com",
    "getnowtoday.com",
    "getsimpleemail.com",
    "gett.icu",
    "gexik.com",
    "ggmal.ml",
    "giantmail.de",
    "ginzi.be",
    "ginzi.co.uk",
    "ginzi.es",
    "ginzi.net",
    "ginzi.org",
    "ginzi.us",
    "girlsalbum.com",
    "girlx.org",
    "giveh2o.com",
    "givememail.org",
    "givmail.com",
    "gixenmixen.com",
    "glitch.sx",
    "globaltourtravel.com",
    "glubex.com",
    "glucosegrin.com",
    "gmal.com",
    "gmatch.org",
    "gmial.com",
    "gmx.us.com",
    "gnctr-calgari.com",
    "gnctr-denizli.com",
    "go.irc.so",
    "go2site.com",
    "go2vn.com",
    "goemailgo.com",
    "golem.zgu.de",
    "gomail.pgojual.com",
    "gomail2020.com",
    "gonrei.de",
    "goooogle.com",
    "goplaygame.nl",
    "gorillaswithdirtyarmpits.com",
    "goround.info",
    "gosuslugi-spravka.ru",
    "gothere4.com",
    "gotmail.com",
    "gotmail.net",
    "gotmail.org",
    "gowikibooks.com",
    "gowikicampus.com",
    "gowikicars.com",
    "gowikifilms.com",
    "gowikigames.com",
    "gowikimusic.com",
    "gowikinetwork.com",
    "gowikitravel.com",
    "gowikitv.com",
    "grandmamail.com",
    "grandmasmail.com",
    "great-host.in",
    "greencafe24.com",
    "greendays.com",
    "greenhousemail.com",
    "greensloth.com",
    "greggamel.com",
    "greggamel.net",
    "gregorsky.zone",
    "gregorygamel.com",
    "gregorygamel.net",
    "grish.de",
    "griuc.schule",
    "grobmail.com",
    "grossmail.com",
    "groupbuffet.com",
    "grugrug.ru",
    "gruz-m.ru",
    "gs-6976.myds.me",
    "gsx2.ga",
    "gudanglowongan.com",
    "guerrillamail.au",
    "guerrillamail.hu",
    "guerrillamail.jp",
    "guerrillamail.ru",
    "guerrillamail.se",
    "guerrillamail.us",
    "guerrillamail.co",
    "guerrillamail.nl",
    "guerrillamail.pl",
    "guerrillamail.co.uk",
    "guerrillamail.com.de",
    "guerrillamail.de.com",
    "guerrillamail.org",
    "guerrillamail.info",
    "guerrillamail.net",
    "guerrillamail.biz",
    "guerrillamail.org",
]);
/**
 * Common weak passwords that should be rejected
 */
const COMMON_WEAK_PASSWORDS = new Set([
    "password",
    "password1",
    "password123",
    "password123!",
    "password1234",
    "password12345",
    "123456",
    "1234567",
    "12345678",
    "123456789",
    "1234567890",
    "password123!",
    "password1234!",
    "qwerty",
    "qwerty123",
    "qwertyuiop",
    "abc123",
    "letmein",
    "welcome",
    "welcome1",
    "admin",
    "admin123",
    "administrator",
    "root",
    "toor",
    "login",
    "login123",
    "passw0rd",
    "iloveyou",
    "monkey",
    "dragon",
    "master",
    "master123",
    "sunshine",
    "princess",
    "football",
    "baseball",
    "soccer",
    "hockey",
    "batman",
    "superman",
    "trustno1",
    "shadow",
    "shadow123",
    "ashley",
    "bailey",
    "passw0rd",
    "qwertyuiop",
    "mustang",
    "michael",
    "jennifer",
    "jordan",
    "hunter",
    "hunter2",
    "amanda",
    "summer",
    "love",
    "hello",
    "hello123",
    "charlie",
    "donald",
    "password!",
    "qwerty1",
    "whatever",
    "freedom",
    "nothing",
    "cheese",
    "computer",
    "starwars",
]);
/**
 * Default configuration for abuse prevention
 */
export const DEFAULT_ABUSE_PREVENTION_CONFIG = {
    minPasswordLength: 8,
    maxPasswordLength: 128,
    requireUppercase: true,
    requireLowercase: true,
    requireNumbers: true,
    requireSpecialChars: true,
    blockDisposableEmails: true,
    maxEmailLength: 254, // RFC 5321 max length
    suspiciousPatternThreshold: 50,
};
/**
 * Normalize an email address for consistent comparison and storage.
 * - Trims whitespace
 * - Converts to lowercase
 * - Removes dots from Gmail addresses (optional, not enabled by default for privacy)
 *
 * @param email - The email address to normalize
 * @returns Normalized email address
 */
export function normalizeEmail(email) {
    return email.trim().toLowerCase();
}
/**
 * Extract the domain from an email address.
 *
 * @param email - The email address
 * @returns The domain portion of the email
 */
export function extractEmailDomain(email) {
    const normalized = normalizeEmail(email);
    const atIndex = normalized.lastIndexOf("@");
    if (atIndex === -1 || atIndex === normalized.length - 1) {
        return "";
    }
    return normalized.slice(atIndex + 1);
}
/**
 * Check if a domain is a known disposable email provider.
 *
 * @param domain - The domain to check
 * @returns True if the domain is disposable
 */
export function isDisposableDomain(domain) {
    return DISPOSABLE_EMAIL_DOMAINS.has(domain.toLowerCase());
}
/**
 * Validate email format according to RFC 5322 (simplified).
 * This is a practical validation that catches most invalid emails
 * while allowing valid edge cases.
 *
 * @param email - The email address to validate
 * @param config - Abuse prevention configuration
 * @returns Email validation result with details
 */
export function validateEmail(email, config = DEFAULT_ABUSE_PREVENTION_CONFIG) {
    const errors = [];
    const warnings = [];
    let suspicionScore = 0;
    // Check for empty email
    if (!email || typeof email !== "string") {
        return {
            isValid: false,
            normalizedEmail: "",
            domain: "",
            errors: ["Email is required"],
            warnings: [],
            isDisposable: false,
            isSuspicious: false,
            suspicionScore: 100,
        };
    }
    // Normalize the email
    const normalizedEmail = normalizeEmail(email);
    const domain = extractEmailDomain(normalizedEmail);
    // Check email length
    if (normalizedEmail.length > config.maxEmailLength) {
        errors.push(`Email must not exceed ${config.maxEmailLength} characters`);
    }
    // Basic email format validation
    // This regex is more permissive than strict RFC 5322 but catches most issues
    const emailRegex = /^[^\s@"<>()\[\]\\,;:]+@[^\s@"<>()\[\]\\,;:]+\.[^\s@"<>()\[\]\\,;:]+$/;
    if (!emailRegex.test(normalizedEmail)) {
        errors.push("Invalid email format");
    }
    // Check for common format issues
    if (normalizedEmail.startsWith("@") || normalizedEmail.endsWith("@")) {
        errors.push("Email cannot start or end with @");
    }
    if (normalizedEmail.includes("@@")) {
        errors.push("Email cannot contain consecutive @ symbols");
    }
    // Check domain
    if (!domain) {
        errors.push("Email must have a valid domain");
    }
    else {
        // Check if domain has a TLD
        if (!domain.includes(".") || domain.split(".").pop().length < 2) {
            errors.push("Email domain must have a valid TLD");
        }
        // Check for disposable email
        if (config.blockDisposableEmails && isDisposableDomain(domain)) {
            errors.push("Disposable email addresses are not allowed");
            suspicionScore += 80;
        }
    }
    // Calculate suspicion score based on patterns
    // Check for suspiciously long local part (before @)
    const localPart = normalizedEmail.split("@")[0] || "";
    if (localPart.length > 64) {
        warnings.push("Email local part is unusually long");
        suspicionScore += 20;
    }
    // Check for random-looking patterns
    if (looksLikeRandomString(localPart)) {
        warnings.push("Email local part appears randomly generated");
        suspicionScore += 30;
    }
    // Check for numeric-only local part
    if (/^\d+$/.test(localPart)) {
        warnings.push("Email local part consists only of numbers");
        suspicionScore += 40;
    }
    // Check for repeating patterns
    if (hasRepeatingPattern(localPart)) {
        warnings.push("Email contains repeating patterns");
        suspicionScore += 15;
    }
    const isSuspicious = suspicionScore >= config.suspiciousPatternThreshold;
    return {
        isValid: errors.length === 0,
        normalizedEmail,
        domain,
        errors,
        warnings,
        isDisposable: isDisposableDomain(domain),
        isSuspicious,
        suspicionScore,
    };
}
/**
 * Check if a string looks like it was randomly generated.
 * Uses heuristics like character distribution and patterns.
 *
 * @param str - The string to analyze
 * @returns True if the string appears random
 */
export function looksLikeRandomString(str) {
    if (str.length < 8)
        return false;
    // Check for high ratio of consonants (typical of random strings)
    const consonants = (str.match(/[bcdfghjklmnpqrstvwxyz]/gi) || []).length;
    const vowels = (str.match(/[aeiou]/gi) || []).length;
    if (vowels === 0 && consonants > 6)
        return true;
    // Random strings often have unusual character distribution
    const uniqueChars = new Set(str.toLowerCase()).size;
    if (str.length > 10 && uniqueChars / str.length > 0.8)
        return true;
    // Check for random-looking patterns like "xjkwq" or "qpzm"
    const consecutiveConsonants = str.match(/[bcdfghjklmnpqrstvwxyz]{4,}/gi);
    if (consecutiveConsonants && consecutiveConsonants.length > 0)
        return true;
    return false;
}
/**
 * Check for repeating patterns in a string that might indicate automation.
 *
 * @param str - The string to check
 * @returns True if repeating patterns are found
 */
export function hasRepeatingPattern(str) {
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
    const charCounts = new Map();
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
 * Validate password strength against security requirements.
 *
 * @param password - The password to validate
 * @param config - Abuse prevention configuration
 * @returns Password validation result with strength score
 */
export function validatePassword(password, config = DEFAULT_ABUSE_PREVENTION_CONFIG) {
    const errors = [];
    const warnings = [];
    let strengthScore = 0;
    // Check for empty password
    if (!password || typeof password !== "string") {
        return {
            isValid: false,
            errors: ["Password is required"],
            warnings: [],
            strengthScore: 0,
        };
    }
    // Check minimum length
    if (password.length < config.minPasswordLength) {
        errors.push(`Password must be at least ${config.minPasswordLength} characters`);
    }
    else {
        strengthScore += 20;
    }
    // Check maximum length (prevent DoS via hashing)
    if (password.length > config.maxPasswordLength) {
        errors.push(`Password must not exceed ${config.maxPasswordLength} characters`);
    }
    // Check for uppercase letters
    const hasUppercase = /[A-Z]/.test(password);
    if (config.requireUppercase && !hasUppercase) {
        errors.push("Password must contain at least one uppercase letter");
    }
    else if (hasUppercase) {
        strengthScore += 15;
    }
    // Check for lowercase letters
    const hasLowercase = /[a-z]/.test(password);
    if (config.requireLowercase && !hasLowercase) {
        errors.push("Password must contain at least one lowercase letter");
    }
    else if (hasLowercase) {
        strengthScore += 15;
    }
    // Check for numbers
    const hasNumbers = /[0-9]/.test(password);
    if (config.requireNumbers && !hasNumbers) {
        errors.push("Password must contain at least one number");
    }
    else if (hasNumbers) {
        strengthScore += 15;
    }
    // Check for special characters
    const hasSpecialChars = /[!@#$%^&*()_+\-=\[\]{};':"\\|,.<>\/?`~]/.test(password);
    if (config.requireSpecialChars && !hasSpecialChars) {
        errors.push("Password must contain at least one special character");
    }
    else if (hasSpecialChars) {
        strengthScore += 15;
    }
    // Check for common weak passwords
    const lowerPassword = password.toLowerCase();
    if (COMMON_WEAK_PASSWORDS.has(lowerPassword)) {
        errors.push("Password is too common. Please choose a more unique password");
        strengthScore = Math.min(strengthScore, 10);
    }
    // Check for sequences
    if (hasSequentialChars(password)) {
        warnings.push("Password contains sequential characters which reduce security");
        strengthScore -= 10;
    }
    // Check for keyboard patterns
    if (hasKeyboardPattern(password)) {
        warnings.push("Password contains keyboard patterns which reduce security");
        strengthScore -= 10;
    }
    // Bonus for length beyond minimum
    if (password.length >= 12) {
        strengthScore += 10;
    }
    if (password.length >= 16) {
        strengthScore += 10;
    }
    // Bonus for character variety
    const uniqueChars = new Set(password.toLowerCase()).size;
    if (uniqueChars >= password.length * 0.6) {
        strengthScore += 10;
    }
    // Ensure score is within bounds
    strengthScore = Math.max(0, Math.min(100, strengthScore));
    return {
        isValid: errors.length === 0,
        errors,
        warnings,
        strengthScore,
    };
}
/**
 * Check for sequential characters in a string (e.g., "abc", "123", "cba").
 *
 * @param str - The string to check
 * @returns True if sequential characters are found
 */
export function hasSequentialChars(str) {
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
export function hasKeyboardPattern(str) {
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
        if (lower.includes(pattern) ||
            lower.includes(pattern.split("").reverse().join(""))) {
            return true;
        }
    }
    return false;
}
/**
 * Calculate a delay time for rate limiting based on failed attempts.
 * Uses exponential backoff to deter brute force attacks.
 *
 * @param failedAttempts - Number of failed attempts
 * @param baseDelayMs - Base delay in milliseconds
 * @param maxDelayMs - Maximum delay in milliseconds
 * @returns Delay time in milliseconds
 */
export function calculateBackoffDelay(failedAttempts, baseDelayMs = 1000, maxDelayMs = 30000) {
    if (failedAttempts <= 0)
        return 0;
    // Exponential backoff with jitter
    const delay = Math.min(baseDelayMs * Math.pow(2, failedAttempts - 1), maxDelayMs);
    // Add 10% jitter to prevent thundering herd
    const jitter = delay * 0.1 * Math.random();
    return Math.floor(delay + jitter);
}
/**
 * Create a timing-safe comparison for sensitive strings.
 * Helps prevent timing attacks when comparing tokens or hashed values.
 *
 * @param a - First string to compare
 * @param b - Second string to compare
 * @returns True if strings are equal
 */
export function timingSafeEqual(a, b) {
    if (a.length !== b.length) {
        return false;
    }
    let result = 0;
    for (let i = 0; i < a.length; i++) {
        result |= a.charCodeAt(i) ^ b.charCodeAt(i);
    }
    return result === 0;
}
/**
 * Add a constant-time delay to prevent timing attacks.
 * Useful for operations that should take a consistent amount of time
 * regardless of whether they succeed or fail.
 *
 * @param targetTimeMs - Target time in milliseconds for the operation
 * @param startTime - Start time (from performance.now() or Date.now())
 */
export async function addTimingDelay(targetTimeMs, startTime) {
    const elapsed = Date.now() - startTime;
    const remaining = targetTimeMs - elapsed;
    if (remaining > 0) {
        await new Promise((resolve) => setTimeout(resolve, remaining));
    }
}
/**
 * Get statistics about the disposable email domain list.
 * Useful for monitoring and testing.
 *
 * @returns Object with domain count
 */
export function getDisposableEmailStats() {
    return {
        domainCount: DISPOSABLE_EMAIL_DOMAINS.size,
    };
}
/**
 * Get statistics about the weak password list.
 * Useful for monitoring and testing.
 *
 * @returns Object with password count
 */
export function getWeakPasswordStats() {
    return {
        passwordCount: COMMON_WEAK_PASSWORDS.size,
    };
}
