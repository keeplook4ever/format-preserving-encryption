package com.lennon.attackdemo.fpe;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

/**
 * 简化 FPE 引擎（演示用）
 * - alphabet: "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz" (62 chars)
 * - encrypt/decrypt 保持长度，非 alphabet 字符透传
 * - 注意：该实现并非标准 FPE（如 FF1），仅用于演示可逆变换与密钥穷举测试
 */
public final class SimpleFpeEngine {

    private static final String ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";
    private static final int ALPHABET_SIZE = ALPHABET.length();

    private final byte[] key;

    public SimpleFpeEngine(byte[] key) {
        this.key = key.clone();
    }

    private byte[] hmacSha256(byte[] data) {
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private int shiftForPosition(String tweak, int pos, int round) {
        // 构造 ctx = tweak || ":" || pos || ":" || round
        String ctx = tweak + ":" + pos + ":" + round;
        byte[] digest = hmacSha256(ctx.getBytes(StandardCharsets.UTF_8));
        // take first 4 bytes as unsigned int and mod alphabet size
        int v = ((digest[0] & 0xff) << 24) | ((digest[1] & 0xff) << 16) |
                ((digest[2] & 0xff) << 8) | (digest[3] & 0xff);
        if (v < 0) v = -v;
        return v % ALPHABET_SIZE;
    }

    public String encrypt(String plain, String tweak, int rounds) {
        StringBuilder sb = new StringBuilder(plain);
        for (int r = 0; r < rounds; r++) {
            for (int i = 0; i < sb.length(); i++) {
                char ch = sb.charAt(i);
                int idx = ALPHABET.indexOf(ch);
                if (idx < 0) continue; // passthrough
                int shift = shiftForPosition(tweak, i, r);
                int nidx = (idx + shift) % ALPHABET_SIZE;
                sb.setCharAt(i, ALPHABET.charAt(nidx));
            }
        }
        return sb.toString();
    }

    public String decrypt(String cipher, String tweak, int rounds) {
        StringBuilder sb = new StringBuilder(cipher);
        for (int r = rounds - 1; r >= 0; r--) {
            for (int i = 0; i < sb.length(); i++) {
                char ch = sb.charAt(i);
                int idx = ALPHABET.indexOf(ch);
                if (idx < 0) continue; // passthrough
                int shift = shiftForPosition(tweak, i, r);
                int nidx = (idx - shift) % ALPHABET_SIZE;
                if (nidx < 0) nidx += ALPHABET_SIZE;
                sb.setCharAt(i, ALPHABET.charAt(nidx));
            }
        }
        return sb.toString();
    }
}
