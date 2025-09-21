package com.lennon.security.field;

import com.lennon.security.alphabet.Alphabet;
import com.lennon.security.spi.FpeEngine;

import java.util.Arrays;

public final class FieldProcessorFactory {

    private FieldProcessorFactory() {}

    /**
     * 邮箱：只加密 local-part，域名保留
     * marker 可选，比如 "#"
     */
    public static FieldProcessor email(FpeEngine engine, String tweak, String marker) {
        return new FieldProcessor() {
            private final RegexFormatter delegate = new RegexFormatter(
                    engine,
                    "^([A-Za-z0-9._%+\\-]+)(@[A-Za-z0-9.-]+\\.[A-Za-z]{2,})$",
                    Arrays.asList(
                            new RegexFormatter.GroupRule(1, Alphabet.of(Alphabet.Kind.EMAIL_LOCAL),
                                    tweak == null ? "email:v1" : tweak)
                    )
            );

            @Override
            public String encrypt(String plain) {
                String enc = delegate.encrypt(plain);
                return marker == null ? enc : enc + marker;
            }

            @Override
            public String decrypt(String cipher) {
                String c = cipher;
                if (marker != null && c.endsWith(marker)) {
                    c = c.substring(0, c.length() - marker.length());
                }
                return delegate.decrypt(c);
            }
        };
    }

    /**
     * 手机号：默认保留前3后4，中间加密
     * kind = DIGITS 或 BASE62
     */
    public static FieldProcessor phone(FpeEngine engine, String tweak,
                                       Alphabet.Kind kind, int keepPrefix, int keepSuffix) {
        int encLen = 11 - keepPrefix - keepSuffix;
        String regex = "^([0-9]{" + keepPrefix + "})([0-9A-Za-z]{" + encLen + "})([0-9]{"
                + keepSuffix + "})$";
        // 正则：([前三位])([中间若干位])([后四位])
//        String regex = "^([0-9]{" + keepPrefix + "})([0-9]{"
//                + (11 - keepPrefix - keepSuffix) + "})([0-9]{" + keepSuffix + "})$";

        return new RegexFormatter(
                engine,
                regex,
                Arrays.asList(
                        new RegexFormatter.GroupRule(
                                2, Alphabet.of(kind == null ? Alphabet.Kind.DIGITS : kind),
                                tweak == null ? "phone:v1" : tweak
                        )
                )
        );
    }

    /**
     * 中国身份证18位：加密前17位，校验位（最后一位）保持
     */
    public static FieldProcessor chinaId18(FpeEngine engine, String tweak) {
        return new RegexFormatter(
                engine,
                "^([1-9]\\d{5})(\\d{8})(\\d{3})([0-9Xx])$",
                Arrays.asList(
                        new RegexFormatter.GroupRule(1, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "cnid" : tweak) + ":addr"),
                        new RegexFormatter.GroupRule(2, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "cnid" : tweak) + ":birth"),
                        new RegexFormatter.GroupRule(3, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "cnid" : tweak) + ":seq")
                        // group4 = 校验位保留
                )
        );
    }

    /**
     * 信用卡16位：加密中间9位，BIN6和校验位保留
     */
    public static FieldProcessor creditCard16(FpeEngine engine, String tweak) {
        return new RegexFormatter(
                engine,
                "^(\\d{6})(\\d{9})(\\d)$",
                Arrays.asList(
                        new RegexFormatter.GroupRule(2, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "cc" : tweak) + ":mid")
                        // group1 BIN, group3 check digit 保留
                )
        );
    }

    /**
     * 中国护照：1字母 + 8数字，只加密数字部分
     */
    public static FieldProcessor passportCN(FpeEngine engine, String tweak) {
        return new RegexFormatter(
                engine,
                "^([A-Za-z])(\\d{8})$",
                Arrays.asList(
                        new RegexFormatter.GroupRule(2, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "passport" : tweak) + ":num")
                )
        );
    }

    /**
     * 通用护照：1–2字母 + 7–8数字
     */
    public static FieldProcessor passportGeneric(FpeEngine engine, String tweak) {
        return new RegexFormatter(
                engine,
                "^([A-Za-z]{1,2})(\\d{7,8})$",
                Arrays.asList(
                        new RegexFormatter.GroupRule(2, Alphabet.of(Alphabet.Kind.DIGITS),
                                (tweak == null ? "passport" : tweak) + ":num")
                )
        );
    }

    /**
     * 通用：整段加密，用 BASE62
     */
    public static FieldProcessor generic(FpeEngine engine, String tweak) {
        return new RegexFormatter(
                engine,
                "^(.*)$",
                Arrays.asList(
                        new RegexFormatter.GroupRule(1, Alphabet.of(Alphabet.Kind.BASE62),
                                tweak == null ? "generic:v1" : tweak)
                )
        );
    }
}
