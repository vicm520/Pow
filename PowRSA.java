import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicLong;


public class PowRSA {
    
    private static final int RSA_KEY_SIZE = 2048;
    private static final String HASH_ALGORITHM = "SHA-256";
    private static final String SIGNATURE_ALGORITHM = "SHA256withRSA";
    private static final int THREAD_COUNT = Runtime.getRuntime().availableProcessors();
    
    public static void main(String[] args) {
        try {
            System.out.println("=== 高级RSA非对称加密+工作量证明（POW） ===\n");

            int difficulty = args.length > 0 ? Integer.parseInt(args[0]) : 4;
            String nickname = args.length > 1 ? args[1] : "chumeng";
            
            System.out.println("配置参数:");
            System.out.println("- 难度等级: " + difficulty + " 前导零");
            System.out.println("- 昵称: " + nickname);
            System.out.println("- 密度: " + THREAD_COUNT);
            System.out.println("- RSA密钥长度: " + RSA_KEY_SIZE + " 位\n");

            System.out.println("1. 正在生成RSA密钥对...");
            long startTime = System.currentTimeMillis();
            KeyPair keyPair = generateRSAKeyPair();
            long keyGenTime = System.currentTimeMillis() - startTime;
            
            System.out.println("密钥生成已完成 (time: " + keyGenTime + "ms)");

            String publicKeyStr = keyToString(keyPair.getPublic());
            String privateKeyStr = keyToString(keyPair.getPrivate());
            System.out.println("公钥长度: " + publicKeyStr.length() + " 字符");
            System.out.println("私钥长度: " + privateKeyStr.length() + " 字符\n");

            System.out.println("2. 开始多线程POW计算...");
            startTime = System.currentTimeMillis();
            POWResult powResult = performMultiThreadPOW(nickname, difficulty);
            long powTime = System.currentTimeMillis() - startTime;
            
            System.out.println("POW计算已完成!");
            System.out.println("昵称: " + nickname);
            System.out.println("Found nonce: " + powResult.nonce);
            System.out.println("Hash value: " + powResult.hash);
            System.out.println("总计算尝试次数: " + powResult.totalAttempts);
            System.out.println("计算时间: " + powTime + "ms");
            System.out.println("计算速度: " + (powResult.totalAttempts * 1000L / powTime) + " ops/sec\n");

            System.out.println("3. 执行数字签名...");
            String dataToSign = nickname + powResult.nonce;
            byte[] signature = signData(keyPair.getPrivate(), dataToSign);
            String signatureBase64 = Base64.getEncoder().encodeToString(signature);
            
            System.out.println("要签名的数据: " + dataToSign);
            System.out.println("签名长度: " + signature.length + " bytes");
            System.out.println("签名 (Base64): " + signatureBase64.substring(0, Math.min(50, signatureBase64.length())) + "...\n");

            System.out.println("4. 验证数字签名...");
            boolean isValid = verifySignature(keyPair.getPublic(), dataToSign, signature);
            System.out.println("签名验证结果: " + (isValid ? "Success" : "Failed"));

            System.out.println("\n5. 安全性测试...");
            testSignatureSecurity(keyPair.getPublic(), dataToSign, signature);

            System.out.println("\n6. 性能基准...");
            benchmarkOperations(keyPair);
            
        } catch (Exception e) {
            System.err.println("程序执行错误: " + e.getMessage());
            e.printStackTrace();
        }
    }
    
    /**
     *POW工作证明结果
     */
    public static class POWResult {
        public final long nonce;
        public final String hash;
        public final long totalAttempts;
        public final int threadId;
        
        public POWResult(long nonce, String hash, long totalAttempts, int threadId) {
            this.nonce = nonce;
            this.hash = hash;
            this.totalAttempts = totalAttempts;
            this.threadId = threadId;
        }
    }
    
    /**
     * 多线程POW计算
     */
    public static POWResult performMultiThreadPOW(String nickname, int difficulty) throws Exception {
        ExecutorService executor = Executors.newFixedThreadPool(THREAD_COUNT);
        AtomicLong globalNonce = new AtomicLong(0);
        AtomicLong totalAttempts = new AtomicLong(0);
        CountDownLatch latch = new CountDownLatch(1);
        POWResult[] result = new POWResult[1];
        
        // 创建多个工作线程
        for (int i = 0; i < THREAD_COUNT; i++) {
            final int threadId = i;
            executor.submit(() -> {
                try {
                    MessageDigest digest = MessageDigest.getInstance(HASH_ALGORITHM);
                    StringBuilder targetBuilder = new StringBuilder();
                    for (int j = 0; j < difficulty; j++) {
                        targetBuilder.append("0");
                    }
                    String target = targetBuilder.toString();
                    long localNonce = threadId;
                    long localAttempts = 0;
                    
                    while (!Thread.currentThread().isInterrupted()) {
                        localAttempts++;
                        totalAttempts.incrementAndGet();
                        
                        String data = nickname + localNonce;
                        byte[] hashBytes = digest.digest(data.getBytes(StandardCharsets.UTF_8));
                        String hash = bytesToHex(hashBytes);
                        
                        if (hash.startsWith(target)) {
                            synchronized (result) {
                                if (result[0] == null) {
                                    result[0] = new POWResult(localNonce, hash, totalAttempts.get(), threadId);
                                    latch.countDown();
                                    return;
                                }
                            }
                        }
                        
                        localNonce += THREAD_COUNT; // 避免重复计算

                        if (localAttempts % 100000 == 0) {
                            if (result[0] != null) {
                                return;
                            }
                        }
                    }
                } catch (Exception e) {
                    e.printStackTrace();
                }
            });
        }
        
        // 等待结果
        latch.await();
        executor.shutdownNow();
        
        return result[0];
    }
    
    /**
     * 生成RSA密钥对
     */
    public static KeyPair generateRSAKeyPair() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(RSA_KEY_SIZE, new SecureRandom());
        return keyGen.generateKeyPair();
    }
    
    /**
     * 数字签名
     */
    public static byte[] signData(PrivateKey privateKey, String data) throws Exception {
        Signature signature = Signature.getInstance(SIGNATURE_ALGORITHM);
        signature.initSign(privateKey);
        signature.update(data.getBytes(StandardCharsets.UTF_8));
        return signature.sign();
    }
    
    /**
     * 验证签名
     */
    public static boolean verifySignature(PublicKey publicKey, String data, byte[] signature) throws Exception {
        Signature sig = Signature.getInstance(SIGNATURE_ALGORITHM);
        sig.initVerify(publicKey);
        sig.update(data.getBytes(StandardCharsets.UTF_8));
        return sig.verify(signature);
    }
    
    /**
     * 安全性测试
     */
    public static void testSignatureSecurity(PublicKey publicKey, String originalData, byte[] originalSignature) throws Exception {

        String tamperedData = originalData + "tampered";
        boolean test1 = verifySignature(publicKey, tamperedData, originalSignature);
        System.out.println("数据篡改测试: " + (test1 ? "失败-验证通过（异常）" : "通过-验证失败（正常）"));

        byte[] tamperedSignature = originalSignature.clone();
        tamperedSignature[0] = (byte) (tamperedSignature[0] ^ 0xFF);
        boolean test2 = verifySignature(publicKey, originalData, tamperedSignature);
        System.out.println("签名篡改测试: " + (test2 ? "失败-验证通过（异常）" : "通过-验证失败（正常）"));

        boolean test3 = verifySignature(publicKey, "", originalSignature);
        System.out.println("空数据测试: " + (test3 ? "失败-验证通过（异常）" : "通过-验证失败（正常）"));
    }
    
    /**
     * 性能基准
     */
    public static void benchmarkOperations(KeyPair keyPair) throws Exception {
        String testData = "benchmark_test_data_12345";
        int iterations = 1000;

        long startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            signData(keyPair.getPrivate(), testData + i);
        }
        long signTime = System.nanoTime() - startTime;

        byte[] signature = signData(keyPair.getPrivate(), testData);
        startTime = System.nanoTime();
        for (int i = 0; i < iterations; i++) {
            verifySignature(keyPair.getPublic(), testData, signature);
        }
        long verifyTime = System.nanoTime() - startTime;

        System.out.println("平均签名时间: " + (signTime / iterations / 1000000.0) + " ms");
        System.out.println("平均验证时间: " + (verifyTime / iterations / 1000000.0) + " ms");
    }
    
    /**
     * 将字节数组转换为十六进制
     */
    private static String bytesToHex(byte[] bytes) {
        StringBuilder result = new StringBuilder();
        for (byte b : bytes) {
            result.append(String.format("%02x", b));
        }
        return result.toString();
    }
    
    /**
     * 将密钥转换为字符串
     */
    public static String keyToString(Key key) {
        return Base64.getEncoder().encodeToString(key.getEncoded());
    }
    
    /**
     * 将字符串转换为公钥
     */
    public static PublicKey stringToPublicKey(String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }
    
    /**
     * 将字符串转换为私钥
     */
    public static PrivateKey stringToPrivateKey(String keyString) throws Exception {
        byte[] keyBytes = Base64.getDecoder().decode(keyString);
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}