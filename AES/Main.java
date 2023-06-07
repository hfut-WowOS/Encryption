package AES;

public class Main {
    public static void main(String[] args) {
        String secretKey = "2020216774123456"; // 密钥

        // 加密字符串
        String plaintext = "qiming2020216774";
        System.out.println("原始字符串: " + plaintext);

        try {
            String encryptedText = AES.encryptString(plaintext, secretKey);
            System.out.println("加密后的字符串: " + encryptedText);

            String decryptedText = AES.decryptString(encryptedText, secretKey);
            System.out.println("解密后的字符串: " + decryptedText);
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 加密图片
        String imagePath = "../test/test.png";

        try {
            AES.encryptFile(imagePath, secretKey, "../test_aes_en.png");
            AES.decryptFile("../test/test_aes_en.png", secretKey, "../test/test_aes_de.png");
        } catch (Exception e) {
            e.printStackTrace();
        }

        // 加密文本文件
        String textFilePath = "../test/test.txt";

        try {
            AES.encryptFile(textFilePath, secretKey, "../test/test_aes_en.txt");
            AES.decryptFile("../test/test_aes_en.txt", secretKey, "../test/test_aes_de.txt");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
