package com.lennon.security.core;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.Objects;

/**
 * Format preserving business wrapper.
 *
 * API (kept/added):
 *  - encryptEmailWithMarker / decryptEmailWithMarker
 *  - encryptPhoneKeepPrefix / decryptPhoneKeepPrefix
 *  - (backwards-compatible) encryptPhoneKeepEnds / decryptPhoneKeepEnds -> delegate to KeepPrefix methods
 *
 * See earlier comments for behavior details.
 */
public final class FormatPreservingService {
    private final FF1BcEngineWithFormat digitsEngine;    // 只输出数字的 engine
    private final FF1BcEngineWithAlphabet alphabetEngine; // 可输出字母 + 数字的 engine

    public FormatPreservingService(FF1BcEngineWithFormat digitsEngine, FF1BcEngineWithAlphabet alphabetEngine) {
        this.digitsEngine = digitsEngine;
        this.alphabetEngine = alphabetEngine;
    }

    // ---------- 新增：手机号中间允许产生字母的加解密（保留前 keepPrefix 位和后 keepSuffix 位） ----------
    public String encryptPhoneKeepEndsAllowLetters(String phone, int keepPrefix, int keepSuffix) throws Exception {
        if (phone == null) return null;

        // collect characters that alphabetEngine considers part of alphabet (for phone we assume alphabet contains 0-9A-Za-z...)
        StringBuilder coreBuilder = new StringBuilder();
        for (int i = 0; i < phone.length(); i++) {
            char c = phone.charAt(i);
            if (alphabetEngine.containsChar(c)) coreBuilder.append(c);
        }
        String core = coreBuilder.toString();
        if (core.length() == 0) return phone;

        if (keepPrefix < 0) keepPrefix = 0;
        if (keepSuffix < 0) keepSuffix = 0;
        if (core.length() < (keepPrefix + keepSuffix)) {
            // nothing to encrypt (or too short) — return original
            return phone;
        }

        String prefix = core.substring(0, keepPrefix);
        String suffix = core.substring(core.length() - keepSuffix);
        String middle = core.substring(keepPrefix, core.length() - keepSuffix);

        // encrypt middle using alphabet engine (output may contain letters)
        String encMiddle = alphabetEngine.encryptChars(middle);

        String encCore = prefix + encMiddle + suffix;

        // reinsert into original format: iterate original phone, replace characters that are in alphabet with next char from encCore
        StringBuilder out = new StringBuilder();
        int di = 0;
        for (int i = 0; i < phone.length(); i++) {
            char c = phone.charAt(i);
            if (alphabetEngine.containsChar(c)) {
                // take next from encCore
                out.append(encCore.charAt(di++));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }

    public String decryptPhoneKeepEndsAllowLetters(String cipher, int keepPrefix, int keepSuffix) throws Exception {
        if (cipher == null) return null;

        // collect core chars that belong to alphabet (these include digits or letters produced earlier)
        StringBuilder coreBuilder = new StringBuilder();
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            if (alphabetEngine.containsChar(c)) coreBuilder.append(c);
        }
        String core = coreBuilder.toString();
        if (core.length() == 0) return cipher;

        if (keepPrefix < 0) keepPrefix = 0;
        if (keepSuffix < 0) keepSuffix = 0;
        if (core.length() < (keepPrefix + keepSuffix)) {
            return cipher;
        }

        String prefix = core.substring(0, keepPrefix);
        String suffix = core.substring(core.length() - keepSuffix);
        String middle = core.substring(keepPrefix, core.length() - keepSuffix);

        // decrypt middle using alphabet engine (should recover original digits)
        String decMiddle = alphabetEngine.decryptChars(middle);

        String decCore = prefix + decMiddle + suffix;

        // reinsert decrypted core into the cipher's format positions (where alphabetEngine.containsChar was true)
        StringBuilder out = new StringBuilder();
        int di = 0;
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            if (alphabetEngine.containsChar(c)) {
                out.append(decCore.charAt(di++));
            } else {
                out.append(c);
            }
        }
        return out.toString();
    }


    public FormatPreservingService(FF1BcEngineWithFormat digitsEngine) {
        this(digitsEngine, null);
    }

    // ---------------- Email ----------------

    /**
     * Encrypt email local-part, keep domain unchanged.
     * Cipher format: "<encLocal>@<domain>#"
     */
    public String encryptEmailWithMarker(String email) {
        Objects.requireNonNull(email, "email null");
        int at = email.indexOf('@');
        if (at < 0) throw new IllegalArgumentException("not an email: " + email);
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);

        String encLocal;
        if (alphabetEngine != null) {
            try {
                encLocal = alphabetEngine.encryptFormatted(local, false);
            } catch (RuntimeException ex) {
                // fallback to segment-wise
                encLocal = encryptLocalPartNumericSegmentsWithFallback(local);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        } else {
            encLocal = encryptLocalPartNumericSegmentsWithFallback(local);
        }

        return encLocal + "@" + domain + "#";
    }

    /**
     * Decrypt email produced by encryptEmailWithMarker.
     * If marker '#' not present at end, return input unchanged.
     */
    public String decryptEmailWithMarker(String cipher) {
        Objects.requireNonNull(cipher, "cipher null");
        boolean hasMarker = cipher.endsWith("#");
        String base = hasMarker ? cipher.substring(0, cipher.length() - 1) : cipher;
        int at = base.indexOf('@');
        if (at < 0) throw new IllegalArgumentException("not an email: " + cipher);
        String local = base.substring(0, at);
        String domain = base.substring(at + 1);

        if (!hasMarker) return cipher;

        String decLocal;
        if (alphabetEngine != null) {
            try {
                decLocal = alphabetEngine.decryptFormatted(local, false);
            } catch (RuntimeException ex) {
                decLocal = decryptLocalPartNumericSegmentsWithFallback(local);
            } catch (Exception ex) {
                throw new RuntimeException(ex);
            }
        } else {
            decLocal = decryptLocalPartNumericSegmentsWithFallback(local);
        }

        return decLocal + "@" + domain;
    }

    // ---------- phone: preserve prefix/suffix digits ----------
    /**
     * Encrypt phone-like string by keeping first keepPrefix digits and last keepSuffix digits unchanged,
     * replacing only the middle digits. Non-digit formatting characters are preserved in-place.
     *
     * Uses digitsEngine.encryptFormatted on the middle digits.
     */
    public String encryptPhoneKeepPrefix(String phone, int keepPrefix, int keepSuffix) throws Exception {
        Objects.requireNonNull(phone, "phone null");
        if (keepPrefix < 0 || keepSuffix < 0) throw new IllegalArgumentException("keep counts must be >= 0");

        List<Integer> digitPositions = new ArrayList<>();
        StringBuilder digitsOnly = new StringBuilder();
        for (int i = 0; i < phone.length(); i++) {
            char c = phone.charAt(i);
            if (Character.isDigit(c)) {
                digitPositions.add(i);
                digitsOnly.append(c);
            }
        }

        int total = digitsOnly.length();
        if (total == 0) return phone;
        if (keepPrefix + keepSuffix >= total) return phone;

        int midStart = keepPrefix;
        int midEnd = total - keepSuffix;
        String middle = digitsOnly.substring(midStart, midEnd);

        // encrypt middle using digitsEngine (numeric-only string)
        String encMiddle = digitsEngine.encryptFormatted(middle, false);

        // reinsert encrypted middle into original formatted phone
        char[] out = phone.toCharArray();
        int encIndex = 0;
        for (int d = midStart; d < midEnd; d++) {
            int pos = digitPositions.get(d);
            out[pos] = encMiddle.charAt(encIndex++);
        }
        return new String(out);
    }

    public String decryptPhoneKeepPrefix(String cipher, int keepPrefix, int keepSuffix) throws Exception {
        Objects.requireNonNull(cipher, "cipher null");
        if (keepPrefix < 0 || keepSuffix < 0) throw new IllegalArgumentException("keep counts must be >= 0");

        List<Integer> digitPositions = new ArrayList<>();
        StringBuilder digitsOnly = new StringBuilder();
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            if (Character.isDigit(c)) {
                digitPositions.add(i);
                digitsOnly.append(c);
            }
        }

        int total = digitsOnly.length();
        if (total == 0) return cipher;
        if (keepPrefix + keepSuffix >= total) return cipher;

        int midStart = keepPrefix;
        int midEnd = total - keepSuffix;
        String middle = digitsOnly.substring(midStart, midEnd);

        String decMiddle = digitsEngine.decryptFormatted(middle, false);

        char[] out = cipher.toCharArray();
        int decIndex = 0;
        for (int d = midStart; d < midEnd; d++) {
            int pos = digitPositions.get(d);
            out[pos] = decMiddle.charAt(decIndex++);
        }
        return new String(out);
    }

    // ---------- Backwards-compatible aliases ----------
    /**
     * Backwards compatibility: old code/tests may call encryptPhoneKeepEnds(...)
     * Delegate to the new encryptPhoneKeepPrefix(...) implementation.
     */
    @Deprecated
    public String encryptPhoneKeepEnds(String phone, int keepPrefix, int keepSuffix) throws Exception {
        return encryptPhoneKeepPrefix(phone, keepPrefix, keepSuffix);
    }

    @Deprecated
    public String decryptPhoneKeepEnds(String cipher, int keepPrefix, int keepSuffix) throws Exception {
        return decryptPhoneKeepPrefix(cipher, keepPrefix, keepSuffix);
    }

    // ---------- fallback helpers for email local-part numeric segments ----------
    private String encryptLocalPartNumericSegmentsWithFallback(String local) {
        StringBuilder sb = new StringBuilder();
        int i = 0, n = local.length();
        while (i < n) {
            char c = local.charAt(i);
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && Character.isDigit(local.charAt(j))) j++;
                String seg = local.substring(i, j);
                try {
                    String encSeg = digitsEngine.encryptFormatted(seg, false);
                    sb.append(encSeg);
                } catch (IllegalArgumentException ex) {
                    // too short or invalid => leave as-is
                    sb.append(seg);
                } catch (RuntimeException ex) {
                    sb.append(seg);
                } catch (Exception ex) {
                    // convert checked exceptions into runtime here
                    sb.append(seg);
                }
                i = j;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private String decryptLocalPartNumericSegmentsWithFallback(String local) {
        StringBuilder sb = new StringBuilder();
        int i = 0, n = local.length();
        while (i < n) {
            char c = local.charAt(i);
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && Character.isDigit(local.charAt(j))) j++;
                String seg = local.substring(i, j);
                try {
                    String decSeg = digitsEngine.decryptFormatted(seg, false);
                    sb.append(decSeg);
                } catch (IllegalArgumentException ex) {
                    sb.append(seg);
                } catch (RuntimeException ex) {
                    sb.append(seg);
                } catch (Exception ex) {
                    sb.append(seg);
                }
                i = j;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }
}
