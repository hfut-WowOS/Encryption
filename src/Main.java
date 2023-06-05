public class Main {
    public static void main(String[] args) {
        DES des = new DES(2020216774);
        String inputFile = "/Users/qm/Encryption/test/测试图片.png";
        String encryptedFile = inputFile.replace(".", "_des_en.");
        String decryptedFile = inputFile.replace(".", "_des_de.");
        des.encryptFile(inputFile, encryptedFile);
        des.decryptFile(encryptedFile, decryptedFile);
    }
}
