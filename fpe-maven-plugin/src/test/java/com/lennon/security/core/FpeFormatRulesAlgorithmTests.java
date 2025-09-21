package com.lennon.security.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

public class FpeFormatRulesAlgorithmTests {
    private static final Logger log = LoggerFactory.getLogger(FpeFormatRulesAlgorithmTests.class);

    static FF1BcEngineWithFormat digitsEngine;
    static FormatPreservingService fps;

    @BeforeAll
    static void init() {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");
        assertNotNull(hex, "FPE_KEY_HEX must be set for tests");

        byte[] key = hexToBytes(hex);
        byte[] tweak = "tenant:test|field:formatRules".getBytes(StandardCharsets.UTF_8);
        digitsEngine = new FF1BcEngineWithFormat(key, tweak);
        fps = new FormatPreservingService(digitsEngine);
    }

    @Test
    public void email_marker_roundtrip_directService() throws Exception {
        String email = "alice.smith-01_test@example.com";
        String cipher = fps.encryptEmailWithMarker(email);
        log.info("[email] plain={} enc={}", email, cipher);
        // MUST append marker '#'
        assertTrue(cipher.endsWith("#"), "cipher must end with '#'");
        String dec = fps.decryptEmailWithMarker(cipher);
        assertEquals(email, dec, "email must roundtrip");
    }

    @Test
    public void phone_keep_prefix_suffix_roundtrip_directService() throws Exception {
        String phone = "+1-202-555-0173";
        int keepPrefix = 2, keepSuffix = 2;
        String enc = fps.encryptPhoneKeepEnds(phone, keepPrefix, keepSuffix);
        log.info("[phone] plain={} enc={}", phone, enc);
        // verify marker not present for phone
        assertFalse(enc.endsWith("#"));
        String dec = fps.decryptPhoneKeepEnds(enc, keepPrefix, keepSuffix);
        assertEquals(phone, dec, "phone must roundtrip");
        // prefix/suffix digits preserved
        assertPrefixSuffixDigitsEqual(phone, enc, keepPrefix, keepSuffix);
    }

    // helper assertions
    private static void assertPrefixSuffixDigitsEqual(String plain, String enc, int keepPrefix, int keepSuffix) {
        String pd = extractDigits(plain), ed = extractDigits(enc);
        assertEquals(pd.length(), ed.length());
        int total = pd.length();
        for (int i = 0; i < Math.min(keepPrefix, total); i++) assertEquals(pd.charAt(i), ed.charAt(i));
        for (int i = 0; i < Math.min(keepSuffix, total); i++) {
            int idx = total - 1 - i;
            assertEquals(pd.charAt(idx), ed.charAt(idx));
        }
    }
    private static String extractDigits(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) if (Character.isDigit(c)) sb.append(c);
        return sb.toString();
    }
    private static byte[] hexToBytes(String hex) {
        int len = hex.length();
        byte[] out = new byte[len/2];
        for (int i=0;i<out.length;i++){
            int hi = Character.digit(hex.charAt(i*2), 16);
            int lo = Character.digit(hex.charAt(i*2+1),16);
            out[i] = (byte)((hi<<4)|lo);
        }
        return out;
    }
}
