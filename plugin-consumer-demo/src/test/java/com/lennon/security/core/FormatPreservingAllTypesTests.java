package com.lennon.security.core;

import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

import static org.junit.jupiter.api.Assertions.*;

/**
 * Consumer module's lightweight test that matches the fully-qualified name used by surefire in your reactor.
 *
 * - If FPE_KEY_HEX is not present, this test will be skipped.
 * - If FPE_KEY_HEX is present, do a simple smoke round-trip using core classes.
 */
public class FormatPreservingAllTypesTests {
    private static final Logger log = LoggerFactory.getLogger(FormatPreservingAllTypesTests.class);

    @Test
    public void consumerSmoke_roundtrip_ifKeyPresent() throws Exception {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");

        // If no key is supplied, skip this test (we don't want CI to fail when running module without secrets)
        Assumptions.assumeTrue(hex != null && !hex.isEmpty(), "FPE_KEY_HEX not set — skipping smoke test");

        byte[] key = PRF.hexToBytes(hex);
        byte[] tweak = "tenant:demo|suite:consumer-smoke".getBytes(StandardCharsets.UTF_8);

        FF1BcEngineWithFormat digitsEngine = new FF1BcEngineWithFormat(key, tweak);
        String alpha = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-";
        FF1BcEngineWithAlphabet alphaEngine = new FF1BcEngineWithAlphabet(key, alpha, tweak);
        FormatPreservingService fps = new FormatPreservingService(digitsEngine, alphaEngine);

        // sample small round-trip checks
        String phone = "+1-202-555-0173";
        String encPhone = fps.encryptPhoneKeepPrefix(phone, 1, 2);
        String decPhone = fps.decryptPhoneKeepPrefix(encPhone, 1, 2);
        log.info("consumer-smoke phone: {} -> {} -> {}", phone, encPhone, decPhone);
        assertEquals(phone, decPhone);

        String phone_china = "+86-15618940621";
        String encPhone_china = fps.encryptPhoneKeepEndsAllowLetters(phone_china, 3, 4);
        String decPhone_china = fps.decryptPhoneKeepEndsAllowLetters(encPhone_china, 3, 4);
        log.info("cosumer-smoke phonewithLetters: {} -> {} -> {}", phone_china, encPhone_china, decPhone_china);
        assertEquals(phone_china, decPhone_china);

        String email = "alice.smith-01_test@example.com";
        String encEmail = fps.encryptEmailWithMarker(email);
        String decEmail = fps.decryptEmailWithMarker(encEmail);
        log.info("consumer-smoke email: {} -> {} -> {}", email, encEmail, decEmail);
        assertEquals(email, decEmail);


//        String originSample = "This is a sample plain text";
//        String encSample = fps.encryptLocalPartNumericSegmentsWithFallback(originSample);


    }
}
