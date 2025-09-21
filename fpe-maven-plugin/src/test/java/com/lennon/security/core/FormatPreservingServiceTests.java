package com.lennon.security.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;
import org.slf4j.Logger;

/**
 * Tests specifically for new FormatPreservingService API:
 *   - encryptEmailWithMarker / decryptEmailWithMarker
 *   - encryptPhoneKeepPrefix / decryptPhoneKeepPrefix
 */
public class FormatPreservingServiceTests {
    static FF1BcEngineWithFormat digitsEngine;
    static FF1BcEngineWithAlphabet alphabetEngine;
    static FormatPreservingService fps;
    private static final Logger log = LoggerFactory.getLogger(FormatPreservingServiceTests.class);
    @BeforeAll
    public static void init() throws Exception {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");
        assertNotNull(hex, "FPE_KEY_HEX must be set for tests");

        byte[] key = PRF.hexToBytes(hex);
        byte[] tweak = "tenant:test|suite:format".getBytes(StandardCharsets.UTF_8);

        digitsEngine = new FF1BcEngineWithFormat(key, tweak);

        String emailAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-";
        alphabetEngine = new FF1BcEngineWithAlphabet(key, emailAlphabet, tweak);

        fps = new FormatPreservingService(digitsEngine, alphabetEngine);
    }

    private static void logRoundtrip(String label, String plain, String enc, String dec) {
        log.info("[{}] \nplain={}\n enc={}\n dec={}", label, plain, enc, dec);
    }

    @Test
    public void testEmail_encryptEmailWithMarker_roundtrip() throws Exception {
        String plain = "alice.smith-01_test@example.com";
        String enc = fps.encryptEmailWithMarker(plain);
        // should end with '#' marker per API design
        assertTrue(enc.endsWith("#"), "encrypted email should end with marker '#'");
        // decrypt
        String dec = fps.decryptEmailWithMarker(enc);
        logRoundtrip("email",  plain, enc, dec);
        assertEquals(plain, dec, "email should roundtrip via encryptEmailWithMarker/decryptEmailWithMarker");
    }

    @Test
    public void testPhone_encryptPhoneKeepPrefix_roundtrip_commonFormats() throws Exception {
        String[] phones = new String[]{
                "+1-202-555-0173",
                "202 555 0173",
                "(202)555-0173",
                "8615628940601",
                "+6590773423"
        };

        int keepPrefix = 2;
        int keepSuffix = 2;

        for (String plain : phones) {
            String enc = fps.encryptPhoneKeepPrefix(plain, keepPrefix, keepSuffix);
            assertNotNull(enc);
            // ensure formatting characters remain (non-digits positions unchanged)
            // check digits length preserved
            String plainDigits = plain.replaceAll("[^0-9]", "");
            String encDigits = enc.replaceAll("[^0-9]", "");
            assertEquals(plainDigits.length(), encDigits.length(), "digit count must remain same");

            // prefix & suffix digits preserved
            if (plainDigits.length() >= keepPrefix + keepSuffix) {
                assertEquals(plainDigits.substring(0, keepPrefix), encDigits.substring(0, keepPrefix), "prefix digits must be preserved");
                assertEquals(plainDigits.substring(plainDigits.length() - keepSuffix),
                        encDigits.substring(encDigits.length() - keepSuffix), "suffix digits must be preserved");
            }

            // decrypt and verify original
            String dec = fps.decryptPhoneKeepPrefix(enc, keepPrefix, keepSuffix);

            logRoundtrip("phone DIGITS", plain, enc, dec);
            assertEquals(plain, dec, "phone must decrypt back to original");
        }
    }

    @Test
    public void testPhone_encryptPhoneAllowLetters_keepEnds_roundtrip() throws Exception {
        String plain = "+86-15618940601";
        int keepPrefix = 3; // 保留前3位
        int keepSuffix = 2; // 保留后2位

        String enc = fps.encryptPhoneKeepEndsAllowLetters(plain, keepPrefix, keepSuffix);
        assertNotNull(enc);

        // digit/alpha core长度应保持一致
        String plainCore = "";
        for (int i=0;i<plain.length();i++){
            char c = plain.charAt(i);
            if (alphabetEngine.containsChar(c)) plainCore += c;
        }
        String encCore = "";
        for (int i=0;i<enc.length();i++){
            char c = enc.charAt(i);
            if (alphabetEngine.containsChar(c)) encCore += c;
        }
        assertEquals(plainCore.length(), encCore.length(), "core length preserved");

        // 保留的 prefix / suffix 数字应一致
        if (plainCore.length() >= keepPrefix + keepSuffix) {
            assertEquals(plainCore.substring(0, keepPrefix), encCore.substring(0, keepPrefix));
            assertEquals(plainCore.substring(plainCore.length() - keepSuffix),
                    encCore.substring(encCore.length() - keepSuffix));
        }

        String dec = fps.decryptPhoneKeepEndsAllowLetters(enc, keepPrefix, keepSuffix);
        logRoundtrip("phone allow letters", plain, enc, dec);
        assertEquals(plain, dec, "phone should round-trip after allow-letters encryption");
    }
}
