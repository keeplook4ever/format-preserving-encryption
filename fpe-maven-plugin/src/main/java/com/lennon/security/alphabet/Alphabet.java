package com.lennon.security.alphabet;

import java.util.HashMap;
import java.util.Map;
import java.util.Objects;

/**
 * Simple Alphabet mapping: charset is an ordered String of characters (no duplicates).
 * Example: "0123456789" or "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789" etc.
 */
public final class Alphabet {
    private final char[] chars;
    private final Map<Character, Integer> valMap;

    public Alphabet(String charset){
        Objects.requireNonNull(charset, "charset null");
        if (charset.isEmpty()) throw new IllegalArgumentException("charset empty");
        // ensure unique chars
        valMap = new HashMap<>();
        chars = charset.toCharArray();
        for (int i = 0; i < chars.length; i++){
            if (valMap.containsKey(chars[i])) throw new IllegalArgumentException("duplicate char in charset: " + chars[i]);
            valMap.put(chars[i], i);
        }
    }

    public int radix(){ return chars.length; }

    public int toVal(char c){
        Integer v = valMap.get(c);
        if (v == null) throw new IllegalArgumentException("char not in alphabet: " + c);
        return v;
    }

    public char toChar(int v){
        if (v < 0 || v >= chars.length) throw new IllegalArgumentException("value out of range: " + v);
        return chars[v];
    }

    public String getCharset(){ return new String(chars); }
}