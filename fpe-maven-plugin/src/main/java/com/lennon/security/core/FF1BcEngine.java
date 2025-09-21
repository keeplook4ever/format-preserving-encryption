package com.lennon.security.core;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

/**
 * Thin wrapper around BouncyCastle's FPEFF1Engine for digit-only formats (radix=10).
 *
 * Usage:
 *   FF1BcEngine engine = new FF1BcEngine(keyBytes, 10, tweakBytes);
 *   String cipher = engine.encryptDigits("12025550173");    // returns digits string same length
 *   String plain = engine.decryptDigits(cipher);
 */
public final class FF1BcEngine {
    private final byte[] key;
    private final int radix;
    private final byte[] tweak;

    public FF1BcEngine(byte[] key, int radix, byte[] tweak) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("key empty");
        if (radix < 2 || radix > 256) throw new IllegalArgumentException("radix out of range");
        this.key = key.clone();
        this.radix = radix;
        this.tweak = tweak == null ? new byte[0] : tweak.clone();
    }

    /**
     * Encrypt a numeric-only string (digits 0..radix-1). Returns a cipher string same length.
     */
    public String encryptDigits(String plainDigits) {
        byte[] in = digitsToByteArray(plainDigits);
        FPEFF1Engine engine = new FPEFF1Engine();
        engine.init(true, new FPEParameters(new KeyParameter(key), radix, tweak));
        byte[] out = new byte[in.length];
        int written = engine.processBlock(in, 0, in.length, out, 0);
        if (written != out.length) {
            // Most implementations return the same length; otherwise, resize.
            out = Arrays.copyOf(out, written);
        }
        return byteArrayToDigits(out);
    }

    /**
     * Decrypt a numeric cipher produced by encryptDigits.
     */
    public String decryptDigits(String cipherDigits) {
        byte[] in = digitsToByteArray(cipherDigits);
        FPEFF1Engine engine = new FPEFF1Engine();
        engine.init(false, new FPEParameters(new KeyParameter(key), radix, tweak));
        byte[] out = new byte[in.length];
        int written = engine.processBlock(in, 0, in.length, out, 0);
        if (written != out.length) {
            out = Arrays.copyOf(out, written);
        }
        return byteArrayToDigits(out);
    }

    private byte[] digitsToByteArray(String s) {
        if (s == null) throw new IllegalArgumentException("null input");
        byte[] b = new byte[s.length()];
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c < '0' || c > '9') throw new IllegalArgumentException("only digits 0-9 supported in this wrapper");
            b[i] = (byte) (c - '0');
        }
        return b;
    }

    private String byteArrayToDigits(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length);
        for (int i = 0; i < b.length; i++) {
            int v = b[i] & 0xFF;
            if (v < 0 || v >= radix) throw new IllegalStateException("output digit out of range: " + v);
            sb.append((char) ('0' + v));
        }
        return sb.toString();
    }

    /** convenience: tweak from string */
    public static byte[] tweakFromString(String s) {
        return s == null ? new byte[0] : s.getBytes(StandardCharsets.UTF_8);
    }
}
