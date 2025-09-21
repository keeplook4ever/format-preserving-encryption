package com.lennon.security.mojo;

import com.lennon.security.alphabet.Alphabet;
import com.lennon.security.core.FpeStreamShift;
import com.lennon.security.core.PRF;
import com.lennon.security.field.FieldProcessor;
import com.lennon.security.field.FieldProcessorFactory;

import com.lennon.security.spi.FpeEngine;
import org.apache.maven.plugins.annotations.Parameter;
import org.apache.maven.plugin.AbstractMojo;

public abstract class BaseMojo extends AbstractMojo {

    @Parameter(property = "keyHex")
    protected String keyHex;

    @Parameter(property = "tweak", defaultValue = "default-tweak-v1")
    protected String tweak;

    @Parameter(property = "type", defaultValue = "generic") // email | phone | generic
    protected String type;

    @Parameter(property = "text")
    protected String text;

    @Parameter(property = "emailMarker")
    protected String emailMarker; // e.g. "#"

    @Parameter(property = "phoneAlphabet", defaultValue = "DIGITS")
    protected String phoneAlphabet; // DIGITS | BASE62

    @Parameter(property = "phoneKeepPrefix", defaultValue = "3")
    protected int phoneKeepPrefix;

    @Parameter(property = "phoneKeepSuffix", defaultValue = "4")
    protected int phoneKeepSuffix;

    protected FpeEngine engine;

    protected void initEngine() {
        byte[] key;
        if (keyHex != null && !keyHex.isEmpty()){
            key = PRF.hexToBytes(keyHex);
        } else {
            // 尝试环境变量
            String env = System.getenv("FPE_KEY_HEX");
            if (env == null || env.isEmpty()){
                throw new IllegalArgumentException("Missing keyHex (or env FPE_KEY_HEX)");
            }
            key = PRF.hexToBytes(env);
        }
        engine = FpeStreamShift.build(key);
    }

    protected FieldProcessor buildProcessor(){
        switch (type.toLowerCase()){
            case "email":
                return FieldProcessorFactory.email(engine, tweak, emailMarker);
            case "phone":
                Alphabet.Kind kind = "BASE62".equalsIgnoreCase(phoneAlphabet)
                        ? Alphabet.Kind.BASE62 : Alphabet.Kind.DIGITS;
                return FieldProcessorFactory.phone(engine, tweak, kind, phoneKeepPrefix, phoneKeepSuffix);
            case "cnid":       // 中国身份证18位（方案A，不动校验位）
            case "chinaid18":
                return FieldProcessorFactory.chinaId18(engine, tweak);

            case "cc":         // 信用卡16位（方案A）
            case "card16":
                return FieldProcessorFactory.creditCard16(engine, tweak);

            case "passport":   // 中国护照（1字母+8数字）
                return FieldProcessorFactory.passportCN(engine, tweak);
            case "generic":
            default:
                // 通用：按 BASE62 做整段加解
//                return new FieldProcessor() {
//                    @Override public String encrypt(String plain) {
//                        return engine.encrypt(plain, Alphabet.of(Alphabet.Kind.BASE62), tweak);
//                    }
//                    @Override public String decrypt(String cipher) {
//                        return engine.decrypt(cipher, Alphabet.of(Alphabet.Kind.BASE62), tweak);
//                    }
//                };
                return FieldProcessorFactory.generic(engine, tweak);
        }
    }
}
