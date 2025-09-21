package com.lennon.security.spi;

import com.lennon.security.alphabet.Alphabet;
import com.lennon.security.core.PRF;

import java.nio.charset.StandardCharsets;

public final class SimpleStreamFpeEngine implements FpeEngine {
    private final PRF prf;
    private final int rounds;

    public SimpleStreamFpeEngine(byte[] key, int rounds){
        this.prf = new PRF(key);
        this.rounds = Math.max(4, rounds); // 至少4轮
    }

    private byte[] ctx(String tweak, String mode, int pos, int round, int len){
        return PRF.concat(
                PRF.utf8("FPE:STREAMSHIFT"),
                PRF.utf8("|tweak="), PRF.utf8(tweak==null? "":tweak),
                PRF.utf8("|mode="), PRF.utf8(mode),
                PRF.utf8("|pos="), PRF.int32be(pos),
                PRF.utf8("|round="), PRF.int32be(round),
                PRF.utf8("|len="), PRF.int32be(len)
        );
    }

    @Override
    public String encrypt(String plain, Alphabet alphabet, String tweak) {
        char[] arr = plain.toCharArray();
        for (int r=0;r<rounds;r++){
            for (int i=0;i<arr.length;i++){
                char c = arr[i];
                if (!alphabet.contains(c)) continue; // 非字母表字符保持不变（如 @ . - 空格等）
                int shift = prf.hmacMod(ctx(tweak,"enc",i,r,arr.length), alphabet.size());
                int idx = alphabet.idx(c);
                arr[i] = alphabet.sym(idx + shift);
            }
        }
        return new String(arr);
    }

    @Override
    public String decrypt(String cipher, Alphabet alphabet, String tweak) {
        char[] arr = cipher.toCharArray();
        for (int r=rounds-1;r>=0;r--){
            for (int i=0;i<arr.length;i++){
                char c = arr[i];
                if (!alphabet.contains(c)) continue;
                int shift = prf.hmacMod(ctx(tweak,"enc",i,r,arr.length), alphabet.size());
                int idx = alphabet.idx(c);
                arr[i] = alphabet.sym(idx - shift);
            }
        }
        return new String(arr);
    }
}
