package com.lennon.security.core;

import com.lennon.security.spi.FpeEngine;
import com.lennon.security.spi.SimpleStreamFpeEngine;

public final class FpeStreamShift {
    public static FpeEngine build(byte[] key){
        // 默认 8 轮；可改为配置
        return new SimpleStreamFpeEngine(key, 8);
    }
}
