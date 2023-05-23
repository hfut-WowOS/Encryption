package src;

public class Main {
    public static void main(String[] args) {
        String in_path = "测试图片.png";
        String En_path = "en.dat";
        String De_path = "de.png";
        DES des = new DES(Utils.int2BinaryString(2020216774));
        des.EncryptionFile(in_path, En_path);
        String originfilemd5 = MD5.getMD5(in_path);
        des.DecryptionFile(En_path, De_path);
        String newfilemd5 = MD5.getMD5(De_path);
        if (originfilemd5.equals(newfilemd5)) {
            System.out.println("源文件的md5为：" + originfilemd5);
            System.out.println("加密并解密后文件的md5为：" + newfilemd5);
            System.out.println("des测试成功");
        }
        System.out.println(des.Encryption("qiming"));
    }

}
