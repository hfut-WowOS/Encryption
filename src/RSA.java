package src;

import java.math.BigInteger;
import java.util.Random;

public class RSA {
    private final static int numLength = 1024;//素数长度
    private final static int accuracy = 100;//素数的准确率为1-(2^(-accuracy))

    // //获取最大公约数
    // private BigInteger getGCD(BigInteger a, BigInteger b) {
    //     if (b.byteValue() == 0) return a;
    //     return getGCD(b, a.mod(b));
    // }

    //扩展欧几里得方法,计算 ax + by = 1中的x与y的整数解（a与b互质）
    private static BigInteger[] extGCD(BigInteger a, BigInteger b) {
        if (b.signum() == 0) {
            return new BigInteger[]{a, new BigInteger("1"), new BigInteger("0")};
        } else {
            BigInteger[] bigIntegers = extGCD(b, a.mod(b));
            BigInteger y = bigIntegers[1].subtract(a.divide(b).multiply(bigIntegers[2]));
            return new BigInteger[]{bigIntegers[0], bigIntegers[2], y};
        }
    }

    //超大整数超大次幂然后对超大的整数取模，利用蒙哥马利乘模算法,
    //(base ^ exp) mod n
    //依据(a * b) mod n=(a % n)*(b % n) mod n
    private static BigInteger expMode(BigInteger base, BigInteger exp, BigInteger mod) {
        BigInteger res = BigInteger.ONE;
        BigInteger tempBase = new BigInteger(base.toString());
        for (int i = 0; i < exp.bitLength(); i++) {
            if (exp.testBit(i)) {//判断对应二进制位是否为1
                res = (res.multiply(tempBase)).mod(mod);
            }
            tempBase = tempBase.multiply(tempBase).mod(mod);
        }
        return res;
    }

    //产生公钥与私钥
    public static SecretKey generateKey(BigInteger p, BigInteger q) {
        //令n = p * q。取 φ(n) = (p-1) * (q-1)。
        BigInteger n = p.multiply(q);
        //计算与n互质的整数个数 欧拉函数
        BigInteger fy = p.subtract(BigInteger.ONE).multiply(q.subtract(BigInteger.ONE));
        //取 e ∈ [1 < e < φ(n) ] ，( n , e )作为公钥对，这里取65537
        BigInteger e = new BigInteger("65537");
        //计算ed与fy的模反元素d。令 ed mod φ(n)  = 1，计算d，然后将( n , d ) 作为私钥对
        BigInteger[] bigIntegers = extGCD(e, fy);
        //计算出的x不能是负数，如果是负数，则进行x=x+fy。使x为正数，但是x<fy。
        BigInteger x = bigIntegers[1];
        if (x.signum() == -1) {
            x = x.add(fy);
        }
        //返回计算出的密钥
        return new SecretKey(n, e, x);
    }

    public static SecretKey generateKey() {
        BigInteger[] pq = getRandomPQ();
        return generateKey(pq[0], pq[1]);
    }

    //加密
    public static BigInteger encrypt(BigInteger text, SecretKey.PublicKey publicKey) {
        return expMode(text, publicKey.e, publicKey.n);
    }

    //解密
    public static BigInteger decrypt(BigInteger cipher, SecretKey.PrivateKey privateKey) {
        return expMode(cipher, privateKey.d, privateKey.n);
    }

    //加密
    public static String encrypt(String text, SecretKey.PublicKey publicKey) {
        return encrypt(new BigInteger(text.getBytes()), publicKey).toString();
    }

    //解密
    public static String decrypt(String chipper, SecretKey.PrivateKey privateKey) {
        BigInteger bigInteger = expMode(new BigInteger(chipper), privateKey.d, privateKey.n);
        byte[] bytes = new byte[bigInteger.bitLength() / 8 + 1];
        for (int i = 0; i < bytes.length; i++) {
            for (int j = 0; j < 8; j++) {
                if (bigInteger.testBit(j + i * 8)) {
                    bytes[bytes.length - 1 - i] |= 1 << j;
                }
            }
        }
        return new String(bytes);
    }

    //产生两个随机1024位大质数
    public static BigInteger[] getRandomPQ() {
        BigInteger p = BigInteger.probablePrime(numLength, new Random());
        while (!p.isProbablePrime(accuracy)) {
            p = BigInteger.probablePrime(numLength, new Random());
        }
        BigInteger q = BigInteger.probablePrime(numLength, new Random());
        while (!q.isProbablePrime(accuracy)) {
            q = BigInteger.probablePrime(numLength, new Random());
        }
        return new BigInteger[]{p, q};
    }

    //密匙对
    static class SecretKey {
        BigInteger n, e, d;

        public SecretKey(BigInteger n, BigInteger e, BigInteger d) {
            this.n = n;
            this.e = e;
            this.d = d;
        }

        public PublicKey getPublicKey() {
            return new PublicKey(n, e);
        }

        public PrivateKey getPrivateKey() {
            return new PrivateKey(n, d);
        }

        //密钥
        static class PrivateKey {
            public BigInteger n, d;

            public PrivateKey(BigInteger n, BigInteger d) {
                this.n = n;
                this.d = d;
            }
        }

        //公钥
        static class PublicKey {
            public BigInteger n, e;

            public PublicKey(BigInteger n, BigInteger e) {
                this.n = n;
                this.e = e;
            }
        }
    }


    public static void main(String[] args) {
        SecretKey secretKey = RSA.generateKey();
        //明文内容不要超过1024位,超过后需要分段加密
        String text = "Hello world";
        String chipper = RSA.encrypt(text, secretKey.getPublicKey());

        System.out.println("加密后:\n" +
                //密文长度可能会随着随机密钥的改变而改变，最长不超过2048位
                "密文二进制长度:" + new BigInteger(chipper).bitLength()
                + "\n"
                + chipper);
        String origin = RSA.decrypt(chipper, secretKey.getPrivateKey());
        System.out.println("解密后:\n" + origin);
    }
}