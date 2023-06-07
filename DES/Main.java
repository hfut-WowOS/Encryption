public class Main {
    public static void main(String[] args) {
        // 支持视频加密，不要超过30M就行（没写缓冲区可能会比较慢）
        String txt_path = "../test/test.txt";
        String big_png_path = "../test/test.png";
        DES des = new DES(0x123456789L);
        des.encrypt(txt_path, txt_path.replace(".", "des_encrypted."));
        des.decrypt(txt_path.replace(".", "des_encrypted."), txt_path.replace(".", "des_decrypted."));
        des.encrypt(big_png_path, big_png_path.replace(".", "des_encrypted."));
        des.decrypt(big_png_path.replace(".", "des_encrypted."), big_png_path.replace(".", "des_decrypted."));
    }
}
