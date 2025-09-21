# 保留格式加密
### 适应场景
适用于需要保留格式的加密，比如身份证号，手机号，邮箱等加密后格式不变，不影响前端。


### 好处
直接满足了脱敏要求，传统加密需要先解密再脱敏。


# 同类
### AES-256加密

# 安全性
需要保护好密钥，密钥泄漏则有数据被还原破解风险。


# 生产建议
## 使用信封加密+key版本（Envelope encryption + key-version metadata）
### 流程概览：
- 写入
  - 生成随机 DEK (e.g. 256-bit)。 
  - 用 DEK 做 FPE（代替直接用 FPE_KEY_HEX）。 
  - 用 KMS KEK（当前版本）wrap/ encrypt DEK → 得到 wrappedDEK。 
  - 将存储项写成： {ciphertext, wrappedDEK, kekVersion, otherMeta}。
- 读取（解密）：
  - 从元数据读出 wrappedDEK 与 kekVersion。
  - 用 KMS unwrap（或本地 KEK 解密）得到 DEK。
  - 用 DEK 做 FPE decrypt 得到明文。
- 轮换 KEK：
  - 在 KMS 中创建新 KEK（或新的 KEK 版本）；对每条记录仅对 wrappedDEK 进行 rewrap（KMS 提供 re-wrap API 或者先 unwrap 再 wrap）；不需要重做 FPE on ciphertext。

### 优点：
轮换非常快（元数据更新），数据仍可解密；能安全地把 KEK 保存在 KMS（硬件保护），DEK 不暴露长期存储。