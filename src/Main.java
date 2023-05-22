package src;
public class Main {
    public static void main(String[] args) {
        String in_path = "测试图片.png";
        String En_path = "en.dat";
        String De_path = "de.png";
        DES des = new DES(Utils.int2BinaryString(2020216774));
        des.EncryptionFile(in_path, En_path);
        des.DecryptionFile(En_path, De_path);
        System.out.println(des.Encryption("qiming"));

    }

}
