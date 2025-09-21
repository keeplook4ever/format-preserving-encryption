package com.lennon.security.core;

import org.apache.commons.codec.binary.Hex;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;

public final class PRF {
    private final byte[] key;

    public PRF(byte[] key){
        if (key == null || key.length == 0) throw new IllegalArgumentException("key empty");
        this.key = key.clone();
    }

    public byte[] hmac(byte[] data){
        try {
            Mac mac = Mac.getInstance("HmacSHA256");
            mac.init(new SecretKeySpec(key, "HmacSHA256"));
            return mac.doFinal(data);
        } catch (Exception e){
            throw new RuntimeException(e);
        }
    }

    public int hmacMod(byte[] data, int mod){
        byte[] out = hmac(data);
        // convert first 4 bytes to int (unsigned)
        int v = ((out[0]&0xff)<<24) | ((out[1]&0xff)<<16) | ((out[2]&0xff)<<8) | (out[3]&0xff);
        v = v < 0 ? -(v+1) : v;
        return v % mod;
    }

    public static byte[] concat(byte[]... parts){
        int len = 0;
        for (byte[] p: parts) len += p.length;
        byte[] r = new byte[len];
        int o=0;
        for (byte[] p: parts){ System.arraycopy(p,0,r,o,p.length); o+=p.length; }
        return r;
    }

    public static byte[] utf8(String s){ return s.getBytes(StandardCharsets.UTF_8); }

    public static byte[] int32be(int v){
        return new byte[]{
                (byte)((v>>>24)&0xff),
                (byte)((v>>>16)&0xff),
                (byte)((v>>>8)&0xff),
                (byte)(v&0xff)
        };
    }

    public static byte[] hexToBytes(String hex){
        try {
            return Hex.decodeHex(hex.toCharArray());
        } catch (Exception e){
            throw new IllegalArgumentException("Bad hex key", e);
        }
    }
}
