package com.lennon.security.field;

import com.lennon.security.alphabet.Alphabet;
import com.lennon.security.core.FpeStreamShift;
import com.lennon.security.core.PRF;
import com.lennon.security.spi.FpeEngine;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import static org.junit.jupiter.api.Assertions.*;

class FieldProcessorFactoryTest {
    private static final Logger log = LoggerFactory.getLogger(FieldProcessorFactoryTest.class);
    static FpeEngine engine;
    @BeforeAll
    static void init() {

        String hex = System.getProperty("FPE_KEY_HEX");
        if (hex == null || hex.isEmpty()) {
            hex = System.getenv("FPE_KEY_HEX");
        }
        assertNotNull(hex, "FPE_KEY_HEX must be set for tests (system property or env)");
        engine = FpeStreamShift.build(PRF.hexToBytes(hex));
    }
    private static void logRoundtrip(String label, String plain, String enc, String dec) {
        log.info("[{}] \nplain={}\n enc={}\n dec={}", label, plain, enc, dec);
    }
    // ---------------- Email ----------------

    @Test
    @DisplayName("Email: local-part FPE, domain kept, marker appended, reversible")
    void email_encrypt_decrypt_withMarker() {
        String tweak = "email:v1";
        String marker = "#";
        FieldProcessor fp = FieldProcessorFactory.email(engine, tweak, marker);

        String plain = "dswe4esr@163.com";
        String enc = fp.encrypt(plain);
        String dec = fp.decrypt(enc);

        logRoundtrip("Email", plain, enc, dec);
        assertTrue(enc.endsWith(marker));
        assertTrue(enc.contains("@163.com"));
        assertEquals(plain.length() + marker.length(), enc.length());

        assertEquals(plain, dec);

    }

    // ---------------- Phone ----------------

    @Test
    @DisplayName("Phone DIGITS: keep prefix/suffix, middle FPE digits only, reversible")
    void phone_digits_keep3_4() {
        FieldProcessor fp = FieldProcessorFactory.phone(
                engine, "phone:v1", Alphabet.Kind.DIGITS, 3, 4);

        String plain = "13884353625"; // 11位
        String enc = fp.encrypt(plain);
        String dec = fp.decrypt(enc);

        logRoundtrip("phone DIGITS", plain, enc, dec);

        assertEquals(plain.length(), enc.length());
        assertEquals(plain.substring(0, 3), enc.substring(0, 3));              // 前3不变
        assertEquals(plain.substring(plain.length()-4), enc.substring(enc.length()-4)); // 后4不变

        // 中段应全为数字
        String mid = enc.substring(3, enc.length() - 4);
        for (char c : mid.toCharArray()) {
            assertTrue(Alphabet.of(Alphabet.Kind.DIGITS).contains(c), "middle must be digits");
        }

        assertEquals(plain, dec);
    }

    @Test
    @DisplayName("Phone BASE62: keep prefix/suffix, middle may include letters, reversible")
    void phone_base62_keep3_4() {
        FieldProcessor fp = FieldProcessorFactory.phone(
                engine, "phone:v1", Alphabet.Kind.BASE62, 3, 4);

        String plain = "13884353625";
        String enc = fp.encrypt(plain);
        String dec = fp.decrypt(enc);


        logRoundtrip("Phone BASE62", plain, enc, dec);

        String mid = enc.substring(3, enc.length() - 4);
        for (char c : mid.toCharArray()) {
            assertTrue(Alphabet.of(Alphabet.Kind.BASE62).contains(c), "middle must be in BASE62");
        }
        assertEquals(plain, dec);
    }

    // ---------------- China ID 18 ----------------

    @Test
    @DisplayName("China ID 18: last checksum kept, body FPE, reversible")
    void chinaId18_schemeA() {
        FieldProcessor fp = FieldProcessorFactory.chinaId18(engine, "cnid:v1");

        String plain = "11010519491231002X"; // 示例
        assertEquals(18, plain.length());

        String enc = fp.encrypt(plain);
        assertEquals(plain.length(), enc.length());
        // 校验位（最后1位）不变
        assertEquals(plain.charAt(17), enc.charAt(17));

        String dec = fp.decrypt(enc);
        assertEquals(plain, dec);
        logRoundtrip("chinaID", plain, enc, dec);
    }

    // ---------------- Credit Card 16 ----------------

    @Test
    @DisplayName("CreditCard 16: BIN & check digit kept, middle FPE, reversible")
    void creditCard16_schemeA() {
        FieldProcessor fp = FieldProcessorFactory.creditCard16(engine, "cc:v1");

        String plain = "4111111111111111"; // Visa 测试卡；16位
        String enc = fp.encrypt(plain);

        assertEquals(plain.length(), enc.length());
        // BIN6 保留
        assertEquals(plain.substring(0, 6), enc.substring(0, 6));
        // 校验位（最后1位）保留
        assertEquals(plain.charAt(15), enc.charAt(15));

        String dec = fp.decrypt(enc);
        assertEquals(plain, dec);
        logRoundtrip("creditCard16", plain, enc, dec);
    }

    // ---------------- Passport ----------------

    @Test
    @DisplayName("Passport CN: 1 letter + 8 digits, encrypt digits only, reversible")
    void passportCN_schemeA() {
        FieldProcessor fp = FieldProcessorFactory.passportCN(engine, "passport:v1");

        String plain = "E12345678";
        String enc = fp.encrypt(plain);
        String dec = fp.decrypt(enc);

        logRoundtrip("passport", plain, enc, dec);
        assertEquals(plain.length(), enc.length());
        // 首字母保持
        assertEquals(plain.charAt(0), enc.charAt(0));

        // 后8位仍是数字字母表内（这里期望为数字）
        String tail = enc.substring(1);
        for (char c : tail.toCharArray()) {
            assertTrue(Alphabet.of(Alphabet.Kind.DIGITS).contains(c), "digits part must stay digits");
        }

        assertEquals(plain, dec);
    }

    // ---------------- Generic ----------------

    @Test
    @DisplayName("Generic BASE62 stream FPE: reversible, length preserved")
    void generic_base62_roundtrip() {
        FieldProcessor fp = FieldProcessorFactory.generic(engine, "generic:v1");

        String plain = "AbcWE@*^&%$#_+__--=DASDJIQWE qWE aejdawj eilqwjeoiqw joiejioqwejioq wDJSAKLDJSL KJDasD-=++Z019-_";
        String enc = fp.encrypt(plain);
        assertEquals(plain.length(), enc.length());

        String dec = fp.decrypt(enc);
        logRoundtrip("generic", plain, enc, dec);
        assertEquals(plain, dec);
    }
}
