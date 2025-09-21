package com.lennon.attackdemo.attack;

import com.lennon.attackdemo.fpe.SimpleFpeEngine;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.List;
import java.util.Map;

/**
 * 演示性攻击器（仅用于受控测试）
 */
public final class AttackSimulator {
    private static final Logger log = LoggerFactory.getLogger(AttackSimulator.class);

    /**
     * 把一个小整数 candidate 扩展为固定长度的 key bytes（演示用）
     */
    public static byte[] candidateToKey(int candidate, int keyLen) {
        byte[] k = new byte[keyLen];
        for (int i = 0; i < keyLen; i++) {
            k[i] = (byte) ((candidate >>> (8 * (i % 4))) & 0xff);
        }
        return k;
    }

    /**
     * 在 [0, maxCandidates) 范围内穷举 candidate（单线程），
     * 对每个 candidate 构造 key，建立 SimpleFpeEngine，并用已知 pairs 校验。
     *
     * 返回匹配的 candidate（第一个），或 -1 表示未找到。
     */
    public static int bruteForceSmallKeyspace(List<Map.Entry<String, String>> knownPairs,
                                              int maxCandidates, int keyLen,
                                              String tweak, int rounds) {
        log.info("Start brute-force: maxCandidates={}, keyLen={}, tweak={}, rounds={}",
                maxCandidates, keyLen, tweak, rounds);

        for (int cand = 0; cand < maxCandidates; cand++) {
            if (cand % 1000000 == 0) {
                log.info("Tried candidate {}", cand);
            }
            byte[] key = candidateToKey(cand, keyLen);
            SimpleFpeEngine engine = new SimpleFpeEngine(key);
            boolean ok = true;
            for (Map.Entry<String, String> p : knownPairs) {
                String enc = engine.encrypt(p.getKey(), tweak, rounds);
                if (!enc.equals(p.getValue())) {
                    ok = false;
                    break;
                }
            }
            if (ok) {
                log.info("Found candidate key = {} (hex {})", cand, bytesToHex(key));
                return cand;
            }
        }
        log.info("No match found in given space");
        return -1;
    }

    public static String bytesToHex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }
}
