package com.lennon.security.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Comprehensive format-preserving tests for multiple data types:
 *  - email (localpart preserved domain + marker)
 *  - passport (alphanumeric)
 *  - national id (18-char with trailing 'X')
 *  - credit card (spaces/hyphens)
 *  - phone numbers (preserve prefix/suffix digits)
 *
 * Requires environment or system property FPE_KEY_HEX to be set.
 */
public class FormatPreservingAllTypesTests {
    private static final Logger log = LoggerFactory.getLogger(FormatPreservingAllTypesTests.class);

    static FF1BcEngineWithFormat digitsEngine;
    static FF1BcEngineWithAlphabet alphabetEngine;
    static FormatPreservingService fps;

    @BeforeAll
    public static void init() throws Exception {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");
        assertNotNull(hex, "FPE_KEY_HEX must be set for tests (system property or env)");

        byte[] key = PRF.hexToBytes(hex);
        byte[] tweak = "tenant:test|suite:format".getBytes(StandardCharsets.UTF_8);

        // digits engine for numeric-only segments
        digitsEngine = new FF1BcEngineWithFormat(key, tweak);

        // alphabet engine that supports 0-9 + a-z + A-Z + some safe punctuation
//        String alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-";
        String asciiVisibleAlphabet =
                "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "!@#$%^&*()_+-=[]{}|;:',.<>/?`~\\\"";
        alphabetEngine = new FF1BcEngineWithAlphabet(key, asciiVisibleAlphabet, tweak);

        // service orchestrator used by higher-level tests
        fps = new FormatPreservingService(digitsEngine, alphabetEngine);
    }

    private static void logRoundtrip(String label, String plain, String enc, String dec) {
        log.info("[{}] \nplain={}\n enc={}\n dec={}", label, plain, enc, dec);
    }

    // ---------------- Email ----------------
    @Test
    public void email_with_marker_roundtrip() throws Exception {
        String plain = "alice.smith-01_test@example.com";
        String enc = fps.encryptEmailWithMarker(plain);
        assertNotNull(enc);
        assertTrue(enc.endsWith("#"), "encrypted email should end with marker '#'");
        String dec = fps.decryptEmailWithMarker(enc);
        logRoundtrip("email", plain, enc, dec);
        assertEquals(plain, dec);
    }

    // ---------------- Passport (alphanumeric) ----------------
    @Test
    public void passport_roundtrip_examples() throws Exception {
        // common passport forms: letter + digits
        String[] passports = new String[] { "G12345678", "P98765432", "A00011122" };
        for (String plain : passports) {
            // use alphabet engine (alphanumeric)
            String enc = alphabetEngine.encryptFormatted(plain, false);
            assertNotNull(enc);
            assertNotEquals(plain, enc, "enc should differ from plain in typical cases");
            String dec = alphabetEngine.decryptFormatted(enc, false);
            logRoundtrip("passport", plain, enc, dec);
            assertEquals(plain, dec);
        }
    }

    // ---------------- National ID (example: Chinese 18-digit with possible trailing 'X') ----------------
    @Test
    public void nationalId_roundtrip_example() throws Exception {
        // Example (18 chars, last may be 'X')
        String plain = "11010519491231002X";
        // use alphabet engine because last char may be 'X'
        String enc = alphabetEngine.encryptFormatted(plain, false);
        assertNotNull(enc);
        assertEquals(plain.length(), enc.length(), "length preserved");
        String dec = alphabetEngine.decryptFormatted(enc, false);
        logRoundtrip("national-id", plain, enc, dec);
        assertEquals(plain, dec);
    }

    // ---------------- Credit card (preserve formatting characters) ----------------
    @Test
    public void creditCard_roundtrip_variousFormats() throws Exception {
        String[] cards = new String[] {
                "4111 1111 1111 1111",
                "5500-0000-0000-0004",
                "4242424242424242"
        };
        for (String plain : cards) {
            String enc = digitsEngine.encryptFormatted(plain, false);
            assertNotNull(enc);
            // digits count must remain same when removing non-digits
            String plainDigits = plain.replaceAll("[^0-9]", "");
            String encDigits = enc.replaceAll("[^0-9]", "");
            assertEquals(plainDigits.length(), encDigits.length(), "digit count preserved for card");
            String dec = digitsEngine.decryptFormatted(enc, false);
            logRoundtrip("cc", plain, enc, dec);
            assertEquals(plain, dec);
        }
    }

    // ---------------- Phone: preserve prefix/suffix digits (numeric-only replacement) ----------------
    @Test
    public void phone_keep_prefix_suffix_roundtrip_commonFormats() throws Exception {
        String[] phones = new String[] {
                "+1-202-555-0173",
                "202 555 0173",
                "(202)555-0173",
                "+86 10 1234 5678",
                "0044 20 7946 0958"
        };
        int keepPrefix = 2;
        int keepSuffix = 2;

        for (String plain : phones) {
            String enc = fps.encryptPhoneKeepPrefix(plain, keepPrefix, keepSuffix);
            assertNotNull(enc);
            // digits preservation
            String plainDigits = plain.replaceAll("[^0-9]", "");
            String encDigits = enc.replaceAll("[^0-9]", "");
            assertEquals(plainDigits.length(), encDigits.length(), "digit count preserved");

            if (plainDigits.length() >= keepPrefix + keepSuffix) {
                assertEquals(plainDigits.substring(0, keepPrefix), encDigits.substring(0, keepPrefix));
                assertEquals(plainDigits.substring(plainDigits.length() - keepSuffix),
                        encDigits.substring(encDigits.length() - keepSuffix));
            }

            String dec = fps.decryptPhoneKeepPrefix(enc, keepPrefix, keepSuffix);
            logRoundtrip("phone (digits only)", plain, enc, dec);
            assertEquals(plain, dec);
        }
    }

    // ---------------- Phone: allow letters in middle (if your service implements this) ----------------
    // This test assumes FormatPreservingService has encryptPhoneKeepEndsAllowLetters/decryptPhoneKeepEndsAllowLetters.
    // If your service uses a different name, rename calls accordingly.
    @Test
    public void phone_allow_letters_middle_roundtrip() throws Exception {
        String plain = "+86-15618940601";
        int keepPrefix = 3;
        int keepSuffix = 2;

        // attempt to call allow-letters API on fps; if your API named differently, adjust.
        String enc;
        String dec;
        try {
            // prefer service-level method (if exists)
            enc = fps.encryptPhoneKeepEndsAllowLetters(plain, keepPrefix, keepSuffix);
            dec = fps.decryptPhoneKeepEndsAllowLetters(enc, keepPrefix, keepSuffix);
        } catch (NoSuchMethodError | NoClassDefFoundError err) {
            // Fallback: use alphabetEngine directly (construct encCore from alphabet engine)
            // Build core of characters that alphabetEngine recognizes
            StringBuilder coreBuilder = new StringBuilder();
            for (int i = 0; i < plain.length(); i++) {
                char c = plain.charAt(i);
                if (alphabetEngine.containsChar(c)) coreBuilder.append(c);
            }
            String core = coreBuilder.toString();
            assertTrue(core.length() > 0, "plain must contain alphabet chars");

            if (core.length() < keepPrefix + keepSuffix) {
                // nothing to encrypt
                enc = plain;
                dec = plain;
            } else {
                String prefix = core.substring(0, keepPrefix);
                String suffix = core.substring(core.length() - keepSuffix);
                String middle = core.substring(keepPrefix, core.length() - keepSuffix);

                String encMiddle = alphabetEngine.encryptChars(middle);
                String encCore = prefix + encMiddle + suffix;

                // reinsert
                StringBuilder out = new StringBuilder();
                int di = 0;
                for (int i = 0; i < plain.length(); i++) {
                    char c = plain.charAt(i);
                    if (alphabetEngine.containsChar(c)) {
                        out.append(encCore.charAt(di++));
                    } else {
                        out.append(c);
                    }
                }
                enc = out.toString();

                // decrypt via alphabet engine
                StringBuilder encCoreBuilder = new StringBuilder();
                for (int i = 0; i < enc.length(); i++) {
                    char c = enc.charAt(i);
                    if (alphabetEngine.containsChar(c)) encCoreBuilder.append(c);
                }
                String encCoreStr = encCoreBuilder.toString();
                String encMiddleExtracted = encCoreStr.substring(keepPrefix, encCoreStr.length() - keepSuffix);
                String decMiddle = alphabetEngine.decryptChars(encMiddleExtracted);
                String decCore = encCoreStr.substring(0, keepPrefix) + decMiddle + encCoreStr.substring(encCoreStr.length() - keepSuffix);

                // reinsert decrypted core
                StringBuilder dout = new StringBuilder();
                int di2 = 0;
                for (int i = 0; i < enc.length(); i++) {
                    char c = enc.charAt(i);
                    if (alphabetEngine.containsChar(c)) {
                        dout.append(decCore.charAt(di2++));
                    } else {
                        dout.append(c);
                    }
                }
                dec = dout.toString();
            }
        }

        logRoundtrip("phone allow-letters", plain, enc, dec);
        assertEquals(plain, dec, "allow-letters phone must round-trip after decrypt");
    }

    // ---------------- Mixed additional examples (ID card, driver's license placeholder) ----------------
    @Test
    public void idcard_and_misc_roundtrip_examples() throws Exception {
        String chineseId = "120101199001011234"; // numeric 18 (no X)
        String drivers = "D1234567";             // example driver-license style (alphanumeric)

        // Chinese ID: numeric -> digitsEngine
        String enc1 = digitsEngine.encryptFormatted(chineseId, false);
        String dec1 = digitsEngine.decryptFormatted(enc1, false);
        logRoundtrip("china-id", chineseId, enc1, dec1);
        assertEquals(chineseId, dec1);

        // Driver license: alphanumeric -> alphabet engine
        String enc2 = alphabetEngine.encryptFormatted(drivers, true);
        String dec2 = alphabetEngine.decryptFormatted(enc2, true);
        logRoundtrip("driver-license", drivers, enc2, dec2);
        assertEquals(drivers, dec2);
    }

    @Test
    public void IgnoreTypeEncDec() throws Exception {
//        FormatPreservingService svc = new FormatPreservingService(digitsEngine, alphabetEngine);
        String s1 = "abc-123_DEF@domain.com";
        String c1 = fps.encryptOpaqueAll(s1);
        String p1 = fps.decryptOpaqueAll(c1);
        logRoundtrip("email", s1, c1, p1);
        assertEquals(s1, p1);

        // 纯文本/姓名/地址
        String s2 = "张三-上海No.88，A座-9F";
        String c2 = fps.encryptAnyUnicodeOpaque(s2);
        String p2 = fps.decryptAnyUnicodeOpaque(c2);
        logRoundtrip("addres", s2, c2, p2);
        assertEquals(s2, p2);

        // 账号/订单号
        String s3 = "ORD-2025-10-21-000123";
        String c3 = fps.encryptAnyUnicodeOpaque(s3);
        String p3 = fps.decryptAnyUnicodeOpaque(c3);
        logRoundtrip("orderID", s3, c3, p3);
        assertEquals(s3, p3);
    }

}
