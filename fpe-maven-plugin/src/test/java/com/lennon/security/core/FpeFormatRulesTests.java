package com.lennon.security.core;

import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;

/**
 * 测试：fpe-maven-plugin 的格式规则
 *
 * - 邮箱：加密 local-part，保留 @domain；加密后的字符串会在 domain 之后追加 '#' 作为标记（cipher 中出现），方便区分是否已经加密。
 *   解密逻辑应识别带 '#' 的域并做正确恢复。
 *
 * - 电话：保留前 x 位、后 y 位不变，只加密中间 digit 部分，保留原有非数字分隔符位置。
 *
 * 依赖：FF1BcEngineWithFormat（项目内已有），并且系统/环境变量 FPE_KEY_HEX 必须设置（hex 编码 AES key）。
 */
public class FpeFormatRulesTests {
    private static final Logger log = LoggerFactory.getLogger(FpeFormatRulesTests.class);

    static FF1BcEngineWithFormat digitsEngine;
    static byte[] key;
    static byte[] tweak;

    @BeforeAll
    static void init() {
        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) hex = System.getenv("FPE_KEY_HEX");
        assertNotNull(hex, "FPE_KEY_HEX must be set for tests");
        key = hexToBytes(hex);
        // 测试用 tweak，生产请用更稳健的策略
        tweak = "tenant:test|field:formatRules".getBytes(StandardCharsets.UTF_8);
        digitsEngine = new FF1BcEngineWithFormat(key, tweak);
    }

    // =========================
    // Email 加密规则测试
    // =========================

    @Test
    public void email_localPart_roundtrip_withSuffixMarker() throws Exception {
        String email = "alice.smith-01_test@example.com";
        String cipher = encryptEmailWithMarker(email);
        log.info("[email]\nplain={}\n enc={}", email, cipher);

        // cipher 必须以 domain + '#' 的形式结尾
        assertTrue(cipher.contains("@"), "cipher must contain @");
        assertTrue(cipher.endsWith("#") || cipher.matches(".+@.+#$"), "cipher should append '#' after domain to mark encryption");

        String dec = decryptEmailWithMarker(cipher);
        log.info("[email]\n dec={}", dec);
        assertEquals(email, dec, "email round-trip must equal original");
    }

    /**
     * 将 email 的 local-part 加密，结果格式： encryptedLocal + "@" + domain + "#"（用于标记）
     */
    private static String encryptEmailWithMarker(String email) throws Exception {
        int at = email.indexOf('@');
        if (at < 0) throw new IllegalArgumentException("not an email: " + email);
        String local = email.substring(0, at);
        String domain = email.substring(at + 1);

        // 只对 local 部分做 FPE（假设 local 中只包含 alphabet 可支持的字符，如 0-9a-zA-Z._-）
        // 我们这里直接用 digitsEngine（radix 10）仅对 local 中的数字串做 FPE；
        // 若 local 含字母/符号，建议在工程中使用适当的 alphabet 引擎（FF1BcEngineWithAlphabet）。
        // 为示例简单：对 local 中的每一段连续数字单独加密（保持点/下划线/横线结构）
        String encLocal = encryptLocalPartSegments(local);

        // 构造带 '#' 标记的 cipher：domain 后追加 #
        return encLocal + "@" + domain + "#";
    }

    /**
     * 解密带 '#' 标记的 email。
     * - 如果 domain 之后没有 '#', 则认为未加密直接返回（或抛异常，视策略），这里我们支持两种形式：有 '#' 则解密，否则直接返回输入。
     */
    private static String decryptEmailWithMarker(String cipher) throws Exception {
        if (!cipher.contains("@")) throw new IllegalArgumentException("not an email: " + cipher);
        // 允许末尾有 '#'
        boolean hasMarker = cipher.endsWith("#");
        String base = hasMarker ? cipher.substring(0, cipher.length() - 1) : cipher;
        int at = base.indexOf('@');
        String local = base.substring(0, at);
        String domain = base.substring(at + 1);

        if (!hasMarker) {
            // 未标记为加密，直接返回（或者根据策略抛异常）
            return cipher;
        }

        String decLocal = decryptLocalPartSegments(local);
        return decLocal + "@" + domain;
    }

    // 将 local-part 中连续数字段逐段用 digitsEngine 加密（纯示例策略）
    private static String encryptLocalPartSegments(String local) throws Exception {
        StringBuilder sb = new StringBuilder();
        int i = 0, n = local.length();
        while (i < n) {
            char c = local.charAt(i);
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && Character.isDigit(local.charAt(j))) j++;
                String segment = local.substring(i, j); // 连续数字段
                String encSeg = digitsEngine.encryptFormatted(segment, false); // segment 是纯数字，直接加密
                sb.append(encSeg);
                i = j;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    private static String decryptLocalPartSegments(String encLocal) throws Exception {
        StringBuilder sb = new StringBuilder();
        int i = 0, n = encLocal.length();
        while (i < n) {
            char c = encLocal.charAt(i);
            if (Character.isDigit(c)) {
                int j = i;
                while (j < n && Character.isDigit(encLocal.charAt(j))) j++;
                String seg = encLocal.substring(i, j);
                String decSeg = digitsEngine.decryptFormatted(seg, false);
                sb.append(decSeg);
                i = j;
            } else {
                sb.append(c);
                i++;
            }
        }
        return sb.toString();
    }

    // =========================
    // 电话保留首尾位规则测试
    // =========================

    @Test
    public void phone_partial_encrypt_keepPrefixSuffix_roundtrip() throws Exception {
        // 测试样例集合
        String[] phones = new String[] {
                "+1-202-555-0173",
                "202 555 0173",
                "(202)555-0173",
                "+86 10 1234 5678"
        };

        // 保留前 2 位、后 2 位示例
        int keepPrefix = 2;
        int keepSuffix = 2;

        for (String phone : phones) {
            String enc = encryptPhoneKeepEnds(phone, keepPrefix, keepSuffix);
            String dec = decryptPhoneKeepEnds(enc, keepPrefix, keepSuffix);
            log.info("[phone]\nplain={}\n enc={}\n dec={}", phone, enc, dec);

            // roundtrip 必须相等
            assertEquals(phone, dec, "phone roundtrip must equal original");

            // encrypted 中首尾对应位置的数字应与原始一致（用于保证 prefix/suffix 保留）
            assertPrefixSuffixDigitsEqual(phone, enc, keepPrefix, keepSuffix);
            // 中间数字应已被修改（可能随机，有概率相同，但通常期望不同；这里我们至少断言长度与数字位置都一致）
            assertMiddleLengthSame(phone, enc, keepPrefix, keepSuffix);
        }
    }

    /**
     * 对 phone 做部分加密：保留前 keepPrefix 个数字、后 keepSuffix 个数字，只加密中间数字（忽略分隔符）。
     * 算法：
     *  1) 找到原字符串中所有数字位置和字符
     *  2) 提取要加密的连续数字序列（中间部分，按 digit-order，不按原字符索引）
     *  3) 用 digitsEngine 对中间数字序列进行 FPE（传入纯数字字符串）
     *  4) 将加密后的中间序列逐个替回原字符串的相应数字位置，保留分隔符
     */
    private static String encryptPhoneKeepEnds(String phone, int keepPrefix, int keepSuffix) throws Exception {
        // 记录每个数字的原始位置
        List<Integer> digitPositions = new ArrayList<>();
        StringBuilder digitsOnly = new StringBuilder();
        for (int i = 0; i < phone.length(); i++) {
            char c = phone.charAt(i);
            if (Character.isDigit(c)) {
                digitPositions.add(i);
                digitsOnly.append(c);
            }
        }

        int totalDigits = digitsOnly.length();
        if (totalDigits == 0) return phone;
        if (keepPrefix + keepSuffix >= totalDigits) {
            // 不加密任何中间位，直接返回原串
            return phone;
        }

        int midStartIndex = keepPrefix;                   // 在 digitsOnly 中的开始索引（inclusive）
        int midEndIndex = totalDigits - keepSuffix;       // 在 digitsOnly 中结束索引（exclusive）
        String middle = digitsOnly.substring(midStartIndex, midEndIndex);

        // 对中间纯数字串加密（result 长度 = middle.length）
        String encMiddle = digitsEngine.encryptFormatted(middle, false);

        // 生成结果字符数组（复制原字符串）
        char[] out = phone.toCharArray();
        // 把 encMiddle 按位放回对应的数字位置
        int encPos = 0;
        for (int d = midStartIndex; d < midEndIndex; d++) {
            int strPos = digitPositions.get(d);
            out[strPos] = encMiddle.charAt(encPos++);
        }
        return new String(out);
    }

    private static String decryptPhoneKeepEnds(String cipher, int keepPrefix, int keepSuffix) throws Exception {
        // 逆过程：提取数字位置与数字串，从中间部分解密并放回
        List<Integer> digitPositions = new ArrayList<>();
        StringBuilder digitsOnly = new StringBuilder();
        for (int i = 0; i < cipher.length(); i++) {
            char c = cipher.charAt(i);
            if (Character.isDigit(c)) {
                digitPositions.add(i);
                digitsOnly.append(c);
            }
        }

        int totalDigits = digitsOnly.length();
        if (totalDigits == 0) return cipher;
        if (keepPrefix + keepSuffix >= totalDigits) {
            return cipher;
        }
        int midStartIndex = keepPrefix;
        int midEndIndex = totalDigits - keepSuffix;
        String middle = digitsOnly.substring(midStartIndex, midEndIndex);
        String decMiddle = digitsEngine.decryptFormatted(middle, false);

        // put back
        char[] out = cipher.toCharArray();
        int decPos = 0;
        for (int d = midStartIndex; d < midEndIndex; d++) {
            int strPos = digitPositions.get(d);
            out[strPos] = decMiddle.charAt(decPos++);
        }
        return new String(out);
    }

    // 辅助断言：确保 prefix/suffix 对应的数字位置不变
    private static void assertPrefixSuffixDigitsEqual(String plain, String enc, int keepPrefix, int keepSuffix) {
        List<Integer> pPos = new ArrayList<>();
        List<Character> pDigits = new ArrayList<>();
        for (int i = 0; i < plain.length(); i++) {
            if (Character.isDigit(plain.charAt(i))) {
                pPos.add(i);
                pDigits.add(plain.charAt(i));
            }
        }
        List<Integer> ePos = new ArrayList<>();
        List<Character> eDigits = new ArrayList<>();
        for (int i = 0; i < enc.length(); i++) {
            if (Character.isDigit(enc.charAt(i))) {
                ePos.add(i);
                eDigits.add(enc.charAt(i));
            }
        }
        assertEquals(pPos.size(), ePos.size(), "digit positions count must equal");

        int total = pPos.size();
        // prefix
        for (int i = 0; i < Math.min(keepPrefix, total); i++) {
            assertEquals(pDigits.get(i), eDigits.get(i), "prefix digit must be preserved at digit-index " + i);
        }
        // suffix
        for (int i = 0; i < Math.min(keepSuffix, total); i++) {
            int idx = total - 1 - i;
            assertEquals(pDigits.get(idx), eDigits.get(idx), "suffix digit must be preserved at digit-index " + idx);
        }
    }

    // 辅助断言：中间位长度与原始中间位长度一致
    private static void assertMiddleLengthSame(String plain, String enc, int keepPrefix, int keepSuffix) {
        String pDigits = extractDigits(plain);
        String eDigits = extractDigits(enc);
        int total = pDigits.length();
        if (keepPrefix + keepSuffix >= total) return;
        String pmid = pDigits.substring(keepPrefix, total - keepSuffix);
        String emid = eDigits.substring(keepPrefix, total - keepSuffix);
        assertEquals(pmid.length(), emid.length(), "middle encrypted length must equal original middle length");
        // 可选检查：中间不全相同（随机性），但在极少数密钥/ tweak 也可能一致，故不强制
    }

    private static String extractDigits(String s) {
        StringBuilder sb = new StringBuilder();
        for (char c : s.toCharArray()) if (Character.isDigit(c)) sb.append(c);
        return sb.toString();
    }

    // =========================
    // 小工具
    // =========================

    private static byte[] hexToBytes(String hex) {
        if (hex == null) return null;
        int len = hex.length();
        if ((len & 1) != 0) throw new IllegalArgumentException("hex length odd");
        byte[] out = new byte[len / 2];
        for (int i = 0; i < out.length; i++) {
            int hi = Character.digit(hex.charAt(i * 2), 16);
            int lo = Character.digit(hex.charAt(i * 2 + 1), 16);
            if (hi == -1 || lo == -1) throw new IllegalArgumentException("bad hex");
            out[i] = (byte) ((hi << 4) | lo);
        }
        return out;
    }
}
