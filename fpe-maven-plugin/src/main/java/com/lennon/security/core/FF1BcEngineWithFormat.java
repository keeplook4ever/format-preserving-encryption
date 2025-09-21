package com.lennon.security.core;

import java.util.ArrayList;
import java.util.List;

/**
 * Wrapper around FF1BcEngine (Bouncy Castle) with formatting + Luhn support.
 *
 * Behavior:
 *  - encryptFormatted preserves any non-digit separators and leading '+' by removing them,
 *    encrypting only the digit characters, and re-inserting separators in same positions.
 *  - If keepLuhn==true and input length >= 2, the last digit (Luhn check digit) is not encrypted
 *    (left as-is).
 *
 * NOTE: this implementation assumes radix 10 (digits only). If you need other alphabets,
 * adapt the digit extraction / mapping logic accordingly.
 */
public final class FF1BcEngineWithFormat {
    private final FF1BcEngine engine;

    public FF1BcEngineWithFormat(byte[] key, byte[] tweak) {
        this.engine = new FF1BcEngine(key, 10, tweak);
    }

    /**
     * Encrypts an input string that may contain separators (non-digit characters) and optional leading '+'.
     * If keepLuhn is true, the last digit of the digit sequence is preserved (not encrypted).
     */
    public String encryptFormatted(String input, boolean keepLuhn) {
        FormatStrip fs = stripFormat(input);

        String digits = fs.digits;
        if (digits.length() == 0) return input; // nothing to encrypt

        String toEncrypt;
        String preservedSuffix = "";
        if (keepLuhn && digits.length() >= 1) {
            // preserve last digit (check digit)
            preservedSuffix = digits.substring(digits.length() - 1);
            toEncrypt = digits.substring(0, digits.length() - 1);
            if (toEncrypt.length() == 0) {
                // nothing to encrypt; just reassemble
                return reinsertFormat(fs, digits);
            }
        } else {
            toEncrypt = digits;
        }

        String encDigitsCore = engine.encryptDigits(toEncrypt);
        String encDigits;
        if (keepLuhn && preservedSuffix.length() > 0) {
            encDigits = encDigitsCore + preservedSuffix;
        } else {
            encDigits = encDigitsCore;
        }

        return reinsertFormat(fs, encDigits);
    }

    /**
     * Decrypts a formatted input produced by encryptFormatted.
     * If keepLuhn==true, the last digit is left untouched (not decrypted).
     */
    public String decryptFormatted(String input, boolean keepLuhn) {
        FormatStrip fs = stripFormat(input);

        String digits = fs.digits;
        if (digits.length() == 0) return input;

        String toDecrypt;
        String preservedSuffix = "";
        if (keepLuhn && digits.length() >= 1) {
            preservedSuffix = digits.substring(digits.length() - 1);
            toDecrypt = digits.substring(0, digits.length() - 1);
            if (toDecrypt.length() == 0) {
                return reinsertFormat(fs, digits);
            }
        } else {
            toDecrypt = digits;
        }

        String decDigitsCore = engine.decryptDigits(toDecrypt);
        String decDigits;
        if (keepLuhn && preservedSuffix.length() > 0) {
            decDigits = decDigitsCore + preservedSuffix;
        } else {
            decDigits = decDigitsCore;
        }

        return reinsertFormat(fs, decDigits);
    }

    // ---------- helper: strip/reinsert format ----------

    private static class FormatStrip {
        final String digits;       // only [0-9]
        final boolean hasPlus;     // whether original had a leading '+'
        final List<Integer> nonDigitPos; // positions and chars for non-digits (store indices and char codes)
        final List<Character> nonDigitChars;

        FormatStrip(String digits, boolean hasPlus, List<Integer> nonDigitPos, List<Character> nonDigitChars) {
            this.digits = digits;
            this.hasPlus = hasPlus;
            this.nonDigitPos = nonDigitPos;
            this.nonDigitChars = nonDigitChars;
        }
    }

    private static FormatStrip stripFormat(String s) {
        StringBuilder digits = new StringBuilder();
        boolean hasPlus = false;
        List<Integer> pos = new ArrayList<>();
        List<Character> chs = new ArrayList<>();

        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (i == 0 && c == '+') {
                hasPlus = true;
                pos.add(i);
                chs.add(c);
            } else if (c >= '0' && c <= '9') {
                digits.append(c);
            } else {
                // record non-digit pos relative to original string
                pos.add(i);
                chs.add(c);
            }
        }
        return new FormatStrip(digits.toString(), hasPlus, pos, chs);
    }

    private static String reinsertFormat(FormatStrip fs, String digits) {
        // Reconstruct original-length string by inserting digits into digit positions and reusing non-digit chars
        // We'll build a char array sized to fs.digits.length + fs.nonDigitPos.size()
        int totalLength = digits.length() + fs.nonDigitPos.size();
        // If original had a leading '+' but we stripped it as non-digit, it will be in nonDigitPos/ch list.
        char[] out = new char[totalLength];
        // Fill with placeholders
        for (int i = 0; i < totalLength; i++) out[i] = '\0';

        // Place non-digit chars first
        for (int k = 0; k < fs.nonDigitPos.size(); k++) {
            int idx = fs.nonDigitPos.get(k);
            // idx is original index; but totalLength may equal original length
            if (idx < totalLength) {
                out[idx] = fs.nonDigitChars.get(k);
            }
        }

        // Fill remaining slots with digits in order
        int di = 0;
        for (int i = 0; i < totalLength; i++) {
            if (out[i] == '\0') {
                if (di < digits.length()) {
                    out[i] = digits.charAt(di++);
                } else {
                    // if digits shorter than expected, pad with '0' (shouldn't happen)
                    out[i] = '0';
                }
            }
        }
        return new String(out);
    }
}
