package com.lennon.security.spi;

import com.lennon.security.alphabet.Alphabet;

public interface FpeEngine {
    String encrypt(String plain, Alphabet alphabet, String tweak);
    String decrypt(String cipher, Alphabet alphabet, String tweak);
}
