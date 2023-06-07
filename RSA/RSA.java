package RSA;

import java.math.BigInteger;
import java.security.SecureRandom;

public class RSA {
    public static void main(String[] args) {
        // 生成RSA密钥对
        RSAKeyPair keyPair = generateKeyPair();

        // 获取公钥和私钥
        RSAPublicKey publicKey = keyPair.getPublicKey();
        RSAPrivateKey privateKey = keyPair.getPrivateKey();

        // 要加密的原始数据
        String originalData = "Hello, RSA encryption!";

        // 加密数据
        BigInteger encryptedData = encrypt(originalData, publicKey);

        // 解密数据
        String decryptedData = decrypt(encryptedData, privateKey);

        // 输出结果
        System.out.println("原始数据: " + originalData);
        System.out.println("加密后数据: " + encryptedData);
        System.out.println("解密后数据: " + decryptedData);
    }

    // 生成RSA密钥对
    public static RSAKeyPair generateKeyPair() {
        SecureRandom random = new SecureRandom();
        BigInteger p = BigInteger.probablePrime(1024, random); // 随机生成一个素数 p
        BigInteger q = BigInteger.probablePrime(1024, random); // 随机生成一个素数 q
        BigInteger n = p.multiply(q); // 计算 n = p * q
        BigInteger phiN = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE)); // 计算欧拉函数值 phi(n)

        // 随机选择一个小于 phi(n) 且与 phi(n) 互质的整数 e
        BigInteger e = generateRandomCoprime(phiN);

        // 计算 e 的模反元素 d，满足 d * e ≡ 1 (mod phi(n))
        BigInteger d = e.modInverse(phiN);

        // 返回公钥和私钥
        return new RSAKeyPair(new RSAPublicKey(n, e), new RSAPrivateKey(n, d));
    }

    // 使用公钥加密数据
    public static BigInteger encrypt(String data, RSAPublicKey publicKey) {
        BigInteger message = new BigInteger(data.getBytes()); // 将原始数据转换为大整数
        // 获取公钥指数 exponent 和模数 modulus
        // 使用 message.modPow(publicKey.getExponent(), publicKey.getModulus())
        // 进行模幂运算，将数据加密为一个新的大整数
        // 模幂运算的结果是将 message 的 exponent 次幂取模 modulus
        return message.modPow(publicKey.getExponent(), publicKey.getModulus()); // 使用模幂运算进行加密
    }

    // 使用私钥解密数据
    public static String decrypt(BigInteger encryptedData, RSAPrivateKey privateKey) {
        // 我们将加密数据进行模幂运算，得到解密后的大整数 decryptedMessage
        BigInteger decryptedMessage = encryptedData.modPow(privateKey.getExponent(), privateKey.getModulus()); // 使用模幂运算进行解密
        // 将解密后的大整数转换回字节数组
        return new String(decryptedMessage.toByteArray()); // 将解密后的大整数转换为字符串
    }

    
    // 生成小于 max 且与 max 互质的随机数
    private static BigInteger generateRandomCoprime(BigInteger max) {
        // 创建一个 SecureRandom 实例，它是一种安全的随机数生成器，提供更高的随机性和安全性
        SecureRandom random = new SecureRandom();
        BigInteger randomNumber;
        do {
            // 生成一个 BigInteger 类型的随机数 randomNumber，位长度与 max 相同
            randomNumber = new BigInteger(max.bitLength(), random);
            // 循环停止条件：随机数小于等于 1;随机数大于等于 max;随机数与 max 的最大公约数不等于 1
        } while (randomNumber.compareTo(BigInteger.ONE) <= 0 || randomNumber.compareTo(max) >= 0
                || !randomNumber.gcd(max).equals(BigInteger.ONE));
        return randomNumber;
    }
}

// RSA公钥类
class RSAPublicKey {
    private final BigInteger modulus; // 模数 n
    private final BigInteger exponent; // 公钥指数 e

    public RSAPublicKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }
}

// RSA私钥类
class RSAPrivateKey {
    private final BigInteger modulus; // 模数 n
    private final BigInteger exponent; // 私钥指数 d

    public RSAPrivateKey(BigInteger modulus, BigInteger exponent) {
        this.modulus = modulus;
        this.exponent = exponent;
    }

    public BigInteger getModulus() {
        return modulus;
    }

    public BigInteger getExponent() {
        return exponent;
    }
}

// RSA密钥对类
class RSAKeyPair {
    private final RSAPublicKey publicKey; // 公钥
    private final RSAPrivateKey privateKey; // 私钥

    public RSAKeyPair(RSAPublicKey publicKey, RSAPrivateKey privateKey) {
        this.publicKey = publicKey;
        this.privateKey = privateKey;
    }

    public RSAPublicKey getPublicKey() {
        return publicKey;
    }

    public RSAPrivateKey getPrivateKey() {
        return privateKey;
    }
}
