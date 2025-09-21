# Format Preserving Encryption (mono-repo)

包含：
- `fpe-maven-plugin` — Maven plugin 实现（格式保留加解密/脱敏）
- `fpe-attack-demo` — 本地演示/攻击演示（仅用于授权测试）
- `plugin-consumer-demo` — 消费端示例

**安全重要提示**：请确保**绝对不要**把任何真实密钥提交到仓库。请使用 KMS/Secret Manager 并在 CI 中通过 Secrets 注入密钥。

## 本地构建
在根目录运行：
```bash
mvn -U -DskipTests clean install
```


## 运行攻击演示（仅限本机测试）
```bash
cd fpe-attack-demo
mvn exec:java -Dexec.mainClass="com.lennon.attackdemo.App"
```

## 使用 plugin-consumer-demo
```bash
cd plugin-consumer-demo
mvn validate
```
## 或命令行
```
mvn com.lennon.security:format-preserving-encrypt-maven-plugin:1.0.0:encrypt -Dtype=phone -Dtext=13884353625 -DphoneAlphabet=BASE62 -DphoneKeepPrefix=3 -DphoneKeepSuffix=4
```

## 发布 plugin 到私服（Nexus/Artifactory）
```bash
mvn -pl fpe-maven-plugin -am deploy
```


