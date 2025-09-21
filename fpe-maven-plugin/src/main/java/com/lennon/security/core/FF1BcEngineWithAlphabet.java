package com.lennon.security.core;

import org.bouncycastle.crypto.fpe.FPEFF1Engine;
import org.bouncycastle.crypto.params.FPEParameters;
import org.bouncycastle.crypto.params.KeyParameter;

import java.util.*;

/**
 * Extension: FPE over a custom alphabet (radix = alphabet.length()) that preserves formatting positions.
 *
 * Example usage:
 *   // alphabet includes digits and uppercase letters -> output may contain letters
 *   String alpha = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
 *   FF1BcEngineWithAlphabet eng = new FF1BcEngineWithAlphabet(key, alpha, tweak);
 *   String cipher = eng.encryptFormatted(" +1-202-555-0173 ", true/false keepLuhn);
 */
public final class FF1BcEngineWithAlphabet {
    private final byte[] key;
    private final String alphabet;
    private final int radix;
    private final byte[] tweak;
    private final Map<Character, Integer> toVal;
    private final char[] valToChar;

    public FF1BcEngineWithAlphabet(byte[] key, String alphabet, byte[] tweak) {
        if (key == null || key.length == 0) throw new IllegalArgumentException("key empty");
        if (alphabet == null || alphabet.length() < 2) throw new IllegalArgumentException("alphabet must have length >= 2");
        this.key = key.clone();
        this.alphabet = alphabet;
        this.radix = alphabet.length();
        this.tweak = tweak == null ? new byte[0] : tweak.clone();

        // build mapping
        toVal = new HashMap<>();
        valToChar = alphabet.toCharArray();
        for (int i = 0; i < valToChar.length; i++) {
            char c = valToChar[i];
            if (toVal.containsKey(c)) {
                throw new IllegalArgumentException("alphabet contains duplicate char: " + c);
            }
            toVal.put(c, i);
        }
    }

    /**
     * Encrypt formatted input: preserves non-alphabet characters (positions), optionally preserves last char (keepLuhn-like).
     */
    public String encryptFormatted(String input, boolean keepLast) throws Exception {
        FormatStrip fs = stripFormat(input);
        // fs.alphabetChars only contains characters that are in alphabet
        String s = fs.alphaChars;
        if (s.length() == 0) return input;

        String toEnc;
        String preservedTail = "";
        if (keepLast && s.length() >= 1) {
            preservedTail = s.substring(s.length()-1);
            toEnc = s.substring(0, s.length()-1);
            if (toEnc.length() == 0) {
                return reinsertFormat(fs, s);
            }
        } else {
            toEnc = s;
        }

        String encCore = bcFf1Process(toEnc, true);
        String encAll = keepLast ? encCore + preservedTail : encCore;
        return reinsertFormat(fs, encAll);
    }

    public String decryptFormatted(String input, boolean keepLast) throws Exception {
        FormatStrip fs = stripFormat(input);
        String s = fs.alphaChars;
        if (s.length() == 0) return input;

        String toDec;
        String preservedTail = "";
        if (keepLast && s.length() >= 1) {
            preservedTail = s.substring(s.length()-1);
            toDec = s.substring(0, s.length()-1);
            if (toDec.length() == 0) return reinsertFormat(fs, s);
        } else {
            toDec = s;
        }

        String decCore = bcFf1Process(toDec, false);
        String decAll = keepLast ? decCore + preservedTail : decCore;
        return reinsertFormat(fs, decAll);
    }

    // ---------- internal: FF1 over alphabet ----------

    private String bcFf1Process(String in, boolean forEncrypt) throws Exception {
        byte[] inVals = new byte[in.length()];
        for (int i = 0; i < in.length(); i++) {
            char c = in.charAt(i);
            Integer v = toVal.get(c);
            if (v == null) throw new IllegalArgumentException("char '" + c + "' not in alphabet");
            inVals[i] = (byte) (v & 0xFF);
        }
        FPEFF1Engine engine = new FPEFF1Engine();
        engine.init(forEncrypt, new FPEParameters(new KeyParameter(key), radix, tweak));
        byte[] out = new byte[inVals.length];
        int outLen = engine.processBlock(inVals, 0, inVals.length, out, 0);
        if (outLen != out.length) out = Arrays.copyOf(out, outLen);
        StringBuilder sb = new StringBuilder(out.length);
        for (int i = 0; i < out.length; i++) {
            int v = out[i] & 0xFF;
            if (v < 0 || v >= valToChar.length) throw new IllegalStateException("output value out of range");
            sb.append(valToChar[v]);
        }
        return sb.toString();
    }

    // ---------- formatting helpers (similar to previous) ----------

    private static class FormatStrip {
        final String alphaChars; // concatenation of chars that belong to alphabet in original order
        final List<Integer> nonAlphaPos;
        final List<Character> nonAlphaChars;

        FormatStrip(String alphaChars, List<Integer> nonAlphaPos, List<Character> nonAlphaChars) {
            this.alphaChars = alphaChars;
            this.nonAlphaPos = nonAlphaPos;
            this.nonAlphaChars = nonAlphaChars;
        }
    }

    private FormatStrip stripFormat(String s) {
        StringBuilder sb = new StringBuilder();
        List<Integer> pos = new ArrayList<>();
        List<Character> chs = new ArrayList<>();
        int origLen = s.length();
        for (int i = 0; i < origLen; i++) {
            char c = s.charAt(i);
            if (toVal.containsKey(c)) {
                sb.append(c);
            } else {
                pos.add(i);
                chs.add(c);
            }
        }
        return new FormatStrip(sb.toString(), pos, chs);
    }

    private String reinsertFormat(FormatStrip fs, String alphaChars) {
        int totalLen = alphaChars.length() + fs.nonAlphaPos.size();
        char[] out = new char[totalLen];
        Arrays.fill(out, '\0');
        for (int i = 0; i < fs.nonAlphaPos.size(); i++) {
            int idx = fs.nonAlphaPos.get(i);
            if (idx < totalLen) out[idx] = fs.nonAlphaChars.get(i);
        }
        int di = 0;
        for (int i = 0; i < totalLen; i++) {
            if (out[i] == '\0') {
                if (di < alphaChars.length()) out[i] = alphaChars.charAt(di++);
                else out[i] = ' ';
            }
        }
        return new String(out);
    }
}
