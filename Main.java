import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.util.Vector;

public class Main {
    public static void main(String[] args) {
        String key = "0000001010010110010010001100010000111000001100000011100001100100";
        String in_path = "paragraph.txt";
        String En_path = "en.dat";
        String De_path = "de.dat";
        EncryptionFile(in_path, En_path, key);
        DecryptionFile(En_path, De_path, key);
    }

    public static void EncryptionFile(String path, String enpath, String key) {
        try {
            WriteFile(enpath, Encryption(ReadFile(path), key));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public static void DecryptionFile(String path, String depath, String key) {
        try {
            WriteFile(depath, Decryption(ReadFile(path), key));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static Vector<String> Encryption(Vector<String> list, String key) {
        assert (key.length() == 64);
        Vector<String> res = new Vector<>();
        DES des = new DES(key);
        for (String string : list) {
            assert (string.length() == 64);
            res.add(des.Encryption(string));
        }
        return res;
    }

    private static Vector<String> Decryption(Vector<String> list, String key) {
        assert (key.length() == 64);
        Vector<String> res = new Vector<>();
        DES des = new DES(key);
        for (String string : list) {
            assert (string.length() == 64);
            res.add(des.Decryption(string));
        }
        return res;
    }

    private static void WriteFile(String path, Vector<String> list) throws IOException {
        OutputStream os = new FileOutputStream(path);
        for (String string : list) {
            for (int i = 0; i < 8; i++) {
                byte b = Utils.parse_binString(string.substring(i * 8, i * 8 + 8));
                os.write(b);
            }
        }
        os.close();
    }

    private static Vector<String> ReadFile(String path) {
        File file = new File(path);
        Vector<String> ret = new Vector<>();
        try {
            byte[] content = Utils.readByNIO(file);
            String head = new String();
            for (int i = 0; i < content.length; i++) {
                if (i % 8 == 0) {
                    ret.add(head);
                    head = new String();
                }
                head = head + Utils.byteToBinaryString(content[i]);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        ret.remove(0);
        int last_len = (ret.get(ret.size() - 1)).length();
        if (last_len < 64) {
            StringBuffer append = new StringBuffer(ret.get(ret.capacity() - 1));
            for (int i = 0; i < 64 - last_len; i++) {
                append.append("0");
            }
            ret.set(ret.size() - 1, append.toString());
        }
        return ret;
    }
}
