package com.lennon.security.alphabet;

import java.util.*;

public final class Alphabet {
    public enum Kind { DIGITS, BASE62, EMAIL_LOCAL }

    private final char[] symbols;
    private final Map<Character,Integer> index;

    private Alphabet(char[] symbols) {
        this.symbols = symbols;
        this.index = new HashMap<>(symbols.length * 2);
        for (int i=0;i<symbols.length;i++){
            if (index.put(symbols[i], i) != null) {
                throw new IllegalArgumentException("Duplicate symbol in alphabet: " + symbols[i]);
            }
        }
    }

    public static Alphabet of(Kind kind){
        switch (kind){
            case DIGITS:
                return new Alphabet("0123456789".toCharArray());
            case BASE62:
                return new Alphabet(("0123456789" +
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "abcdefghijklmnopqrstuvwxyz").toCharArray());
            case EMAIL_LOCAL:
                // local-part safe set: letters, digits, '.', '_', '%', '+', '-'
                return new Alphabet(("0123456789" +
                        "ABCDEFGHIJKLMNOPQRSTUVWXYZ" +
                        "abcdefghijklmnopqrstuvwxyz" +
                        "._%+-").toCharArray());
            default:
                throw new IllegalArgumentException("Unknown kind: " + kind);
        }
    }

    public int size(){ return symbols.length; }

    public boolean contains(char c){ return index.containsKey(c); }

    public int idx(char c){
        Integer i = index.get(c);
        if (i == null) throw new IllegalArgumentException("Char not in alphabet: " + c);
        return i;
    }

    public char sym(int i){
        return symbols[((i % symbols.length)+symbols.length)%symbols.length];
    }
}
