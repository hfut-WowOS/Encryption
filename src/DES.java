package src;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStream;
import java.util.Vector;

public class DES {

    private String KEY;
    private Vector<String> SubKeyList = new Vector<>();

    DES(String key) {
        this.KEY = key;
        GenerateSubKey(key);
    }

    private static final int IP[] = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // 逆IP置换表
    private static final int InverseIP[] = {
            40, 8, 48, 16, 56, 24, 64, 32,
            39, 7, 47, 15, 55, 23, 63, 31,
            38, 6, 46, 14, 54, 22, 62, 30,
            37, 5, 45, 13, 53, 21, 61, 29,
            36, 4, 44, 12, 52, 20, 60, 28,
            35, 3, 43, 11, 51, 19, 59, 27,
            34, 2, 42, 10, 50, 18, 58, 26,
            33, 1, 41, 9, 49, 17, 57, 25
    };

    // 扩展置换表 E，将32位扩展至48位
    private static final int E[] = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
    };

    // P置换，32位 -> 32位
    private static final int[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    // 密钥选择（置换）表，64位密钥去掉校验位，选择剩下的56位作为新的密钥。可以发现，去掉校验位的同时还打乱了顺序
    private static final int[] Key = {
            57, 49, 41, 33, 25, 17, 9,
            1, 58, 50, 42, 34, 26, 18,
            10, 2, 59, 51, 43, 35, 27,
            19, 11, 3, 60, 52, 44, 36,
            63, 55, 47, 39, 31, 23, 15,
            7, 62, 54, 46, 38, 30, 22,
            14, 6, 61, 53, 45, 37, 29,
            21, 13, 5, 28, 20, 12, 4
    };

    // 压缩置换，将56位密钥压缩成48位子密钥
    private final static int[] Compress = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // S盒，每个S盒Si是4x16的置换表，6位 -> 4位
    private final int S_BOX[][][] = {
            {
                    { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                    { 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8 },
                    { 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0 },
                    { 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 }
            },
            {
                    { 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                    { 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5 },
                    { 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15 },
                    { 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 }
            },
            {
                    { 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                    { 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1 },
                    { 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7 },
                    { 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 }
            },
            {
                    { 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15 },
                    { 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9 },
                    { 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4 },
                    { 3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 }
            },
            {
                    { 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                    { 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6 },
                    { 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14 },
                    { 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 }
            },
            {
                    { 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                    { 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8 },
                    { 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6 },
                    { 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13 }
            },
            {
                    { 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                    { 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6 },
                    { 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2 },
                    { 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 }
            },
            {
                    { 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7 },
                    { 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2 },
                    { 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8 },
                    { 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 }
            }
    };

    // 每轮左移的位数
    private static final int[] shiftBits = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    private String PermutedChoiceTwo(String s) {
        return transform_string(s, Compress);
    }

    private String PermutedChoiceOne(String s) {
        assert (s.length() == 64);
        return transform_string(s, Key);
    }

    private String transform_string(String s, int[] option_list) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < option_list.length; i++) {
            sb.append(s.charAt(option_list[i] - 1));
        }
        return sb.toString();
    }

    private String IP_transform(String s) {
        return transform_string(s, IP);
    }

    private String RevIp_transform(String s) {
        return transform_string(s, InverseIP);
    }

    private String P_transform(String s) {
        return transform_string(s, P);
    }

    private String ExpansionPermutation(String s) {
        assert (s.length() == 32);
        return transform_string(s, E);
    }

    private String SBoxes(String s) {
        assert (s.length() == 48);
        String res = "";
        // 拆分8个6位子串
        for (int i = 0; i < 8; i++) {
            String sub_s = s.substring(i * 6, i * 6 + 6);
            // 将6位子串中0、5位为x，其余4位为y
            int x = Integer.parseInt("" + sub_s.charAt(0) + sub_s.charAt(5), 2);
            int y = Integer.parseInt(sub_s.substring(1, 5), 2);
            // 从S盒取S[i][x][y]转化为4位
            String ss = Integer.toBinaryString(S_BOX[i][x][y]);
            // 如果长度小于4位则添0补齐4位
            while (4 - ss.length() != 0) {
                ss = "0" + ss;
            }
            res += ss;
        }
        return res;
    }

    /**
     * F轮函数
     * 
     * @param s 32位
     * @return 32位
     */
    private String F_Function(String s, String k, int i) {
        // E拓展：32->48
        String e_s = ExpansionPermutation(s);
        assert (e_s.length() == 48);
        assert (k.length() == 48);
        // 异或：48->48
        String xor_s = Utils.string_xor(k, e_s);
        // S_box: 48->32
        String sbox_s = SBoxes(xor_s);
        // P置换：32->32
        return P_transform(sbox_s);
    }

    // 产生16个子密钥
    private void GenerateSubKey(String k) {
        String key = new String(k);
        assert (key.length() == 64);
        key = PermutedChoiceOne(key);
        String left = key.substring(0, 28);
        String right = key.substring(28, 56);
        // 循环产生16个子密钥
        for (int i = 0; i < 16; i++) {
            // 将两部分分别移位
            left = Utils.shift_left(left, shiftBits[i]);
            right = Utils.shift_left(right, shiftBits[i]);
            String tmp = PermutedChoiceTwo(left + right);
            SubKeyList.add(tmp);
        }
    }

    public String Encryption64(String s) {
        assert (s.length() == 64);
        // IP 置换
        s = IP_transform(s);
        String left = s.substring(0, 32);
        String right = s.substring(32, 64);
        // 循环16轮
        for (int i = 0; i < 16; i++) {
            String f_out = F_Function(right, SubKeyList.get(i), i);
            String temp_string = Utils.string_xor(left, f_out);
            // 更新l_i 和 r_i
            left = right;
            right = temp_string;
        }
        String res = right + left;
        return RevIp_transform(res);
    }

    public String Decryption64(String s) {
        assert (s.length() == 64);
        // IP 置换
        s = IP_transform(s);
        String left = s.substring(0, 32);
        String right = s.substring(32, 64);
        // 循环16轮
        for (int i = 0; i < 16; i++) {
            String f_out = F_Function(right, SubKeyList.get(15 - i), i);
            String temp_string = Utils.string_xor(left, f_out);
            // 更新l_i 和 r_i
            left = right;
            right = temp_string;
        }
        String res = right + left;
        return RevIp_transform(res);
    }

    private void WriteFile(String path, Vector<String> list) throws IOException {
        OutputStream os = new FileOutputStream(path);
        for (String string : list) {
            for (int i = 0; i < string.length() / 8; i++) {
                byte b = Utils.parse_binString(string.substring(i * 8, i * 8 + 8));
                os.write(b);
            }
        }
        os.close();
    }

    private Vector<String> ReadFile(String path) {
        File file = new File(path);
        try {
            byte[] content = Utils.readByNIO(file);
            return Utils.ByteArrayToBinaryVector(content);
        } catch (IOException e) {
            e.printStackTrace();
            return null;
        }
    }

    public void EncryptionFile(String path, String enpath) {
        try {
            WriteFile(enpath, Encryption(ReadFile(path)));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void DecryptionFile(String path, String depath) {
        try {
            WriteFile(depath, Decryption(ReadFile(path)));
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public Vector<String> Encryption(Vector<String> list) {
        assert (KEY.length() == 64);
        Vector<String> res = new Vector<>();
        for (String string : list) {
            // assert (string.length() == 64);
            if (string.length() == 64) {
                res.add(Encryption64(string));
            } else {
                res.add(string);
            }
        }
        return res;
    }

    public Vector<String> Decryption(Vector<String> list) {
        assert (KEY.length() == 64);
        Vector<String> res = new Vector<>();
        for (String string : list) {
            // assert (string.length() == 64);
            if (string.length() == 64) {
                res.add(Decryption64(string));
            } else {
                res.add(string);
            }
        }
        return res;
    }

    public String Encryption(String paragraph) {
        byte[] list = paragraph.getBytes();
        Vector<String> l = Utils.ByteArrayToBinaryVector(list);
        Vector<String> en_l = Encryption(l);
        StringBuffer buffer = new StringBuffer();
        for (String string : en_l) {
            buffer.append(string);
        }
        return buffer.toString();
    }

}