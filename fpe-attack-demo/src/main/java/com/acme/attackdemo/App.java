package com.lennon.attackdemo;

import com.lennon.attackdemo.attack.AttackSimulator;
import com.lennon.attackdemo.fpe.SimpleFpeEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.AbstractMap;
import java.util.Arrays;
import java.util.List;

/**
 * 运行演示：
 * 1) 使用 "real" key derived from small candidate (e.g., 42) 构造 SimpleFpeEngine
 * 2) 加密示例明文，打印密文
 * 3) 在可穷举空间中运行 AttackSimulator.bruteForceSmallKeyspace 来恢复 candidate
 *
 * 运行: mvn -q exec:java
 */
public class App {
    private static final Logger log = LoggerFactory.getLogger(App.class);

    public static void main(String[] args) throws Exception {
        // demo parameters — 都可修改来观察行为
        int trueCandidate = 1223133422;     // the hidden seed representing "real key" (attacker doesn't know)
        int keyLen = 8;             // demo key length (bytes)
        String tweak = "demo:tweak";
        int rounds = 2;

        // prepare real engine
        byte[] trueKey = AttackSimulator.candidateToKey(trueCandidate, keyLen);
        SimpleFpeEngine real = new SimpleFpeEngine(trueKey);

        // plaintext(s) attacker is assumed to know (known-plaintext)
        String plain = "HELLO123"; // must use characters in alphabet (0-9A-Za-z)
        String cipher = real.encrypt(plain, tweak, rounds);

        log.info("Real key candidate (hidden) = {}", trueCandidate);
        log.info("Plain:  {}", plain);
        log.info("Cipher: {}", cipher);

        // attacker collects known pair(s)
        List<java.util.Map.Entry<String, String>> knownPairs = Arrays.asList(
                new AbstractMap.SimpleEntry<>(plain, cipher)
        );

        // attacker brute forces small keyspace
        int maxCandidates = 300_000; // demo: small; increase to see time cost grow
        int found = AttackSimulator.bruteForceSmallKeyspace(knownPairs, maxCandidates, keyLen, tweak, rounds);

        if (found >= 0) {
            log.info("SUCCESS: recovered candidate = {}", found);
        } else {
            log.info("FAILED to recover in given space");
        }
    }
}
