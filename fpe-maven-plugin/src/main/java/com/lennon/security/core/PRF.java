package com.lennon.security.core;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

/**
 * Small PRF / helpers utility used by tests and engines.
 *
 * - hmac(data) -> HMAC-SHA256(key, data)
 * - hmacMod(data, mod) -> map HMAC output to [0, mod)
 * - concat(...) -> concat byte arrays
 * - utf8(String) -> bytes
 * - int32be(int) -> 4-byte big-endian
 * - hexToBytes(hex) -> convert hex string to bytes (no external deps)
 */
public final class PRF {
    private final byte[] key;

    public PRF(byte[] key) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("key empty");
        this.key = key.clone();
    }

    /**
     * Compute HMAC-SHA256(key, data)
     */
    public byte[] hmac(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    /**
     * Compute HMAC and reduce to int modulo `mod`.
     * Uses the first 4 bytes of HMAC (unsigned).
     */
    public int hmacMod(byte[] data, int mod) {
        byte[] out = hmac(data);
        // convert first 4 bytes to int (unsigned)
        int v = ((out[0] & 0xff) << 24) | ((out[1] & 0xff) << 16) | ((out[2] & 0xff) << 8) | (out[3] & 0xff);
        // make non-negative (map Java signed int -> non-negative domain)
        v = v < 0 ? -(v + 1) : v;
        return v % mod;
    }

    /** Concatenate byte arrays */
    public static byte[] concat(byte[]... parts) {
        int len = 0;
        for (byte[] p : parts) {
            if (p != null) len += p.length;
        }
        byte[] r = new byte[len];
        int o = 0;
        for (byte[] p : parts) {
            if (p == null) continue;
            System.arraycopy(p, 0, r, o, p.length);
            o += p.length;
        }
        return r;
    }

    /** UTF-8 bytes */
    public static byte[] utf8(String s) {
        Objects.requireNonNull(s, "s null");
        return s.getBytes(StandardCharsets.UTF_8);
    }

    /** 4-byte big-endian */
    public static byte[] int32be(int v) {
        return new byte[]{
                (byte) ((v >>> 24) & 0xff),
                (byte) ((v >>> 16) & 0xff),
                (byte) ((v >>> 8) & 0xff),
                (byte) (v & 0xff)
        };
    }

    /**
     * Convert a hex string to bytes.
     * Accepts upper/lower case, optional "0x" prefix, requires even number of hex chars after prefix removal.
     */
    public static byte[] hexToBytes(String hex) {
        if (hex == null) throw new IllegalArgumentException("hex null");
        String s = hex.trim();
        if (s.startsWith("0x") || s.startsWith("0X")) s = s.substring(2);
        if ((s.length() & 1) != 0) throw new IllegalArgumentException("hex string must have even length");
        int len = s.length() / 2;
        byte[] out = new byte[len];
        for (int i = 0; i < len; i++) {
            int hi = Character.digit(s.charAt(i * 2), 16);
            int lo = Character.digit(s.charAt(i * 2 + 1), 16);
            if (hi == -1 || lo == -1) throw new IllegalArgumentException("Invalid hex char in: " + s);
            out[i] = (byte) ((hi << 4) + lo);
        }
        return out;
    }
}
