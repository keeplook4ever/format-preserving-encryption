package com.lennon.security.field;

public interface FieldProcessor {
    String encrypt(String plain);
    String decrypt(String cipher);
}
