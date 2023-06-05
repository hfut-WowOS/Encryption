import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

public class PerformanceTest {
    public static void main(String[] args) throws Exception {
        int keySize = 1024;
        int blockSize = 1024;
        int iterations = 1000;

        // DES performance test
        KeyGenerator keyGenerator = KeyGenerator.getInstance("DES");
        SecretKey secretKey = keyGenerator.generateKey();
        Cipher cipher = Cipher.getInstance("DES/ECB/PKCS5Padding");

        long start = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, secretKey);
            byte[] input = new byte[blockSize];
            byte[] output = cipher.doFinal(input);
        }
        long end = System.currentTimeMillis();
        System.out.println("DES encryption time: " + (end - start) + " ms");

        // RSA performance test
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");

        start = System.currentTimeMillis();
        for (int i = 0; i < iterations; i++) {
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            byte[] input = new byte[blockSize];
            byte[] output = cipher.doFinal(input);
        }
        end = System.currentTimeMillis();
        System.out.println("RSA encryption time: " + (end - start) + " ms");
    }
}
