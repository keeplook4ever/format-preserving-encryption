package com.lennon.security.consumer;

import com.lennon.security.core.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;

/**
 * Simple consumer demo that shows how to call the format-preserving service.
 * Usage: run with -DFPE_KEY_HEX=<hex> or set env FPE_KEY_HEX.
 */
public class PluginConsumerDemo {
    private static final Logger log = LoggerFactory.getLogger(PluginConsumerDemo.class);

    public static void main(String[] args) throws Exception {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");

        if (hex == null || hex.isEmpty()) {
            log.info("FPE_KEY_HEX not provided. Example run requires a key. Set -DFPE_KEY_HEX=...");
            return;
        }

        byte[] key = PRF.hexToBytes(hex);
        byte[] tweak = "tenant:demo|app:plugin-consumer-demo".getBytes(StandardCharsets.UTF_8);

        FF1BcEngineWithFormat digitsEngine = new FF1BcEngineWithFormat(key, tweak);
        String emailAlphabet = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._-";
        FF1BcEngineWithAlphabet alphaEngine = new FF1BcEngineWithAlphabet(key, emailAlphabet, tweak);

        FormatPreservingService fps = new FormatPreservingService(digitsEngine, alphaEngine);

        String phone = "+1-202-555-0173";
        String encPhone = fps.encryptPhoneKeepPrefix(phone, 2, 2);
        String decPhone = fps.decryptPhoneKeepPrefix(encPhone, 2, 2);

        log.info("phone plain: {}, enc: {}, dec: {}", phone, encPhone, decPhone);

        String email = "alice.smith-01_test@example.com";
        String encEmail = fps.encryptEmailWithMarker(email);
        String decEmail = fps.decryptEmailWithMarker(encEmail);

        log.info("email plain: {}, enc: {}, dec: {}", email, encEmail, decEmail);
    }
}
