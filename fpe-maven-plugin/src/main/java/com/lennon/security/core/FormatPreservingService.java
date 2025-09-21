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
    private final FF1BcEngineWithFormat digitsEngine;
    private final FF1BcEngineWithAlphabet alphabetEngine; // optional

    public FormatPreservingService(FF1BcEngineWithFormat digitsEngine, FF1BcEngineWithAlphabet alphabetEngine) {
        this.digitsEngine = Objects.requireNonNull(digitsEngine, "digitsEngine required");
        this.alphabetEngine = alphabetEngine; // may be null
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
