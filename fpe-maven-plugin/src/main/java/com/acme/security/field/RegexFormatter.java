package com.lennon.security.field;

import com.lennon.security.alphabet.Alphabet;
import com.lennon.security.spi.FpeEngine;

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * 通用正则驱动格式器：
 * - regex 用捕获分组拆结构
 * - 对需要加密的分组编号，指定 alphabet 与 tweak
 * - 其他分组/字符保留原样
 * - 未匹配时：原样返回（可选改为抛异常）
 */
public final class RegexFormatter implements FieldProcessor {

    public static final class GroupRule {
        public final int groupIndex;
        public final Alphabet alphabet;
        public final String tweak;
        public GroupRule(int groupIndex, Alphabet alphabet, String tweak) {
            this.groupIndex = groupIndex;
            this.alphabet = alphabet;
            this.tweak = tweak;
        }
    }

    private final FpeEngine engine;
    private final Pattern pattern;
    private final Map<Integer, GroupRule> rules;

    public RegexFormatter(FpeEngine engine, String regex, List<GroupRule> groupRules) {
        this.engine = engine;
        this.pattern = Pattern.compile(regex);
        this.rules = new HashMap<>();
        for (GroupRule r : groupRules) {
            rules.put(r.groupIndex, r);
        }
    }

    @Override
    public String encrypt(String plain) {
        Matcher m = pattern.matcher(plain);
        if (!m.matches()) return plain; // 或者抛异常视需求
        StringBuilder sb = new StringBuilder();
        // group 0 是整体，实际分片从1..groupCount
        for (int i = 1; i <= m.groupCount(); i++) {
            String seg = m.group(i);
            GroupRule r = rules.get(i);
            if (r != null) {
                sb.append(engine.encrypt(seg, r.alphabet, r.tweak));
            } else {
                sb.append(seg);
            }
        }
        return sb.toString();
    }

    @Override
    public String decrypt(String cipher) {
        Matcher m = pattern.matcher(cipher);
        if (!m.matches()) return cipher;
        StringBuilder sb = new StringBuilder();
        for (int i = 1; i <= m.groupCount(); i++) {
            String seg = m.group(i);
            GroupRule r = rules.get(i);
            if (r != null) {
                sb.append(engine.decrypt(seg, r.alphabet, r.tweak));
            } else {
                sb.append(seg);
            }
        }
        return sb.toString();
    }
}
