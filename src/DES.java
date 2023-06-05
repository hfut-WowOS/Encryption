import java.util.Vector;
import java.io.*;
import java.nio.ByteBuffer;
import java.nio.channels.FileChannel;
import java.nio.file.Files;
import java.nio.file.Paths;

public class DES {
    private long Key;
    private long[] SubKeyList = new long[16];
    

    DES(long Key) {
        this.Key = Key;
        GenerateSubKey();
    }

    private enum transform_activity {
        IP,
        INVERSE_IP,
        PC1,
        PC2,
        E,
        P,
    }

    // 用于进行各种变换
    private long transform(long data, transform_activity activity, int len) {
        byte[] transform_form = null;
        switch (activity) {
            case IP:            transform_form = IP;                break;
            case INVERSE_IP:    transform_form = Inverse_IP;        break;
            case PC1:           transform_form = PermutedChoiceOne; break;
            case PC2:           transform_form = PermutedChoiceTwo; break;
            case E:             transform_form = E;                 break;
            case P:             transform_form = P;                 break;
            default:    break;
        }
        // 置换表的长度
        //int len = transform_form.length;
        // 用于保存返回值
        long ans = 0;
        for (int i = 1; i <= transform_form.length; i++) {
            // 将第 location 位放到第 i 位
            int location = transform_form[i - 1];
            // 通过右移操作 data >> (len - location)，将位移到最低位，再通过与 1 进行按位与操作 & 1，取出位的值（0 或 1）。
            long bit = (data >> (len - location)) & 1L;
            ans |= (bit << (transform_form.length - i));
        }
        return ans;
    }

    // 密钥选择（置换）表，64位密钥去掉校验位，选择剩下的56位作为新的密钥
    private static final byte[] PermutedChoiceOne = {
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
    private final static byte[] PermutedChoiceTwo = {
            14, 17, 11, 24, 1, 5,
            3, 28, 15, 6, 21, 10,
            23, 19, 12, 4, 26, 8,
            16, 7, 27, 20, 13, 2,
            41, 52, 31, 37, 47, 55,
            30, 40, 51, 45, 33, 48,
            44, 49, 39, 56, 34, 53,
            46, 42, 50, 36, 29, 32
    };

    // 每轮左移的位数
    private static final byte[] shift_Bits = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

    // 生成16个子密钥
    private void GenerateSubKey() {
        // 去除密钥的校验位：64 -> 56
        long trans_key = transform(Key, transform_activity.PC1, 64);
        // 左28位：
        long left = trans_key >>> 28;
        long right = trans_key & 0xFFFFFFF;
        // 循环产生16个子密钥
        for (int i = 0; i < 16; i++) {
            left = shift_left28(left, shift_Bits[i]);
            right = shift_left28(right, shift_Bits[i]);
            // 压缩置换：56 -> 48
            long merged = (left << 28) | (right & 0xFFFFFFF);
            long compress_key = transform(merged, transform_activity.PC2, 56);
            SubKeyList[i] = compress_key;
        }
    }

    // 将28位的子密钥循环移n位
    public static long shift_left28(long number, int n) {
        // long lower28Bits = number & 0xFFFFFFF; // 获取低 28 位
        // long shiftedBits = (lower28Bits << n) | (lower28Bits >>> (28 - n));
        // long result = (number & ~0xFFFFFFF) | (shiftedBits & 0xFFFFFFF);
        // return result;
        return ((number << n) | (number >>> (28 - n))) & 0xFFFFFFF;
    }

    // 初始置换表格
    private static final byte IP[] = {
            58, 50, 42, 34, 26, 18, 10, 2,
            60, 52, 44, 36, 28, 20, 12, 4,
            62, 54, 46, 38, 30, 22, 14, 6,
            64, 56, 48, 40, 32, 24, 16, 8,
            57, 49, 41, 33, 25, 17, 9, 1,
            59, 51, 43, 35, 27, 19, 11, 3,
            61, 53, 45, 37, 29, 21, 13, 5,
            63, 55, 47, 39, 31, 23, 15, 7
    };

    // 逆初始置换表格
    private static final byte Inverse_IP[] = {
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
    private static final byte E[] = {
            32, 1, 2, 3, 4, 5,
            4, 5, 6, 7, 8, 9,
            8, 9, 10, 11, 12, 13,
            12, 13, 14, 15, 16, 17,
            16, 17, 18, 19, 20, 21,
            20, 21, 22, 23, 24, 25,
            24, 25, 26, 27, 28, 29,
            28, 29, 30, 31, 32, 1
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

    // P置换，32位 -> 32位
    private static final byte[] P = {
            16, 7, 20, 21,
            29, 12, 28, 17,
            1, 15, 23, 26,
            5, 18, 31, 10,
            2, 8, 24, 14,
            32, 27, 3, 9,
            19, 13, 30, 6,
            22, 11, 4, 25
    };

    private long SBox(long data) {
        // 分成八个6bit子串
        long res = 0;
        long mask = 0xFC0000000000L; // 掩码，用于提取每6位数字
        int shift = 42; // 右移的位数，每次右移6位
        for (int i = 0; i < 8; i++) {
            int sub_data = (int) ((data & mask) >>> shift);
            mask >>>= 6; // 右移掩码，以便提取下一组数字
            shift -= 6; // 更新右移的位数
            // 取出最高最低两位
            byte x = (byte) ((sub_data >> 5 & 1) * 2 + (sub_data & 1));
            byte y = (byte) ((sub_data >>> 1) & 0b1111);
            res += ((long)(S_BOX[i][x][y]) << (28 - 4 * i));
        }
        return res;
    }

    private long F_Function(long data, long subkey) {
        // E拓展：32->48
        long e_data = transform(data, transform_activity.E, 32);
        // 异或：48->48
        long xor_data = e_data ^ subkey;
        // S_box: 48->32
        data = SBox(xor_data);
        // P置换：32->32
        data = transform(data, transform_activity.P, 32);
        return data;
    }

    // 加密64位整数
    public long encryption64(long data) {
        // IP 置换
        data = transform(data, transform_activity.IP, 64);
        long left = data >>> 32;
        long right = data & 0xFFFFFFFFL;
        // 循环 16 轮
        for (int i = 0; i < 16; i++) {
            long f_res = F_Function(right, SubKeyList[i]);
            long tmp = left ^ f_res;
            left = right;
            right = tmp;
        }
        long res = ((long) right << 32) | (left & 0xFFFFFFFFL);
        // 逆 IP 置换
        return transform(res, transform_activity.INVERSE_IP, 64);
    }

    // 解密64位整数
    public long decryption64(long data) {
        // IP 置换
        data = transform(data, transform_activity.IP, 64);
        long left = data >>> 32;
        long right = data & 0xFFFFFFFF;
        // 循环 16 轮
        for (int i = 0; i < 16; i++) {
            long f_res = F_Function(right, SubKeyList[15 - i]);
            long tmp = left ^ f_res;
            left = right;
            right = tmp;
        }
        long res = ((long) right << 32) | (left & 0xFFFFFFFFL);
        // 逆 IP 置换
        return transform(res, transform_activity.INVERSE_IP, 64);
    }

    public Vector<Long> encrption_list(Vector<Long> list) {
        Vector<Long> res =new Vector<>();
        for (int i = 0; i < list.size(); i++) {
            res.add(encryption64(list.get(i)));
        }
        return res;
    }

    public Vector<Long> decrption_list(Vector<Long> list) {
        Vector<Long> res =new Vector<>();
        for (int i = 0; i < list.size(); i++) {
            res.add(decryption64(list.get(i)));
        }
        return res;
    }

    public void encrption(String filePath, String toPath) {
        Vector<Long> longVector = readFromFile(filePath, 1024);
        Vector<Long> enVector = encrption_list(longVector);
        writeToFile(toPath, enVector);
    }

    public void decrption(String filePath, String toPath) { 
        Vector<Long> longVector = readFromFile(filePath, 1024);
        Vector<Long> deVector = decrption_list(longVector);
        writeToFile(toPath, deVector);
    }

    private static Vector<Long> readFromFile(String filePath, int bufferSize) {
        Vector<Long> longVector = new Vector<>();

        try (FileInputStream fis = new FileInputStream(filePath);
             FileChannel channel = fis.getChannel()) {
            // 创建输入缓冲区
            ByteBuffer inputBuffer = ByteBuffer.allocate(bufferSize);

            // 读取文件内容到输入缓冲区，直到文件结束
            while (channel.read(inputBuffer) != -1) {
                inputBuffer.flip(); // 切换为读模式

                // 将输入缓冲区内容按位分割成长整型数组
                splitBufferToLongVector(inputBuffer, longVector);

                inputBuffer.clear(); // 清空输入缓冲区，准备下一次读取
            }

            // 检查最后一组位数是否不足64位，补足0
            if (inputBuffer.position() % 8 != 0) {
                int remaining = inputBuffer.remaining();
                int padding = 8 - remaining % 8;

                for (int i = 0; i < padding; i++) {
                    inputBuffer.put((byte) 0);
                }

                inputBuffer.flip(); // 切换为读模式
                splitBufferToLongVector(inputBuffer, longVector);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }

        return longVector;
    }

    private static void splitBufferToLongVector(ByteBuffer buffer, Vector<Long> longVector) {
        int numLongs = buffer.remaining() / 8; // 计算需要的长整型数组长度
        for (int i = 0; i < numLongs; i++) {
            long num = 0;
            for (int j = 0; j < 8; j++) {
                num = (num << 8) | (buffer.get() & 0xFF);
            }

            longVector.add(num);
        }
    }

    private static void writeToFile(String filePath, Vector<Long> longVector) {
        if (longVector != null) {
            try (FileOutputStream fos = new FileOutputStream(filePath);
                 FileChannel channel = fos.getChannel()) {
                // 创建输出缓冲区
                ByteBuffer outputBuffer = ByteBuffer.allocate(longVector.size() * 8);
                outputBuffer.flip(); // 切换为读模式
                // 将输出缓冲区内容写入文件
                while (outputBuffer.hasRemaining()) {
                    channel.write(outputBuffer);
                }
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void encryptFile(String inputFile, String encryptedFile) {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(inputFile));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(encryptedFile))) {
            byte[] buffer = new byte[8];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1) {
                long originalData = convertBytesToLong(buffer, bytesRead);
                long encryptedData = encryption64(originalData);
                byte[] encryptedBuffer = convertLongToBytes(encryptedData);
                bos.write(encryptedBuffer);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    public void decryptFile(String encryptedFile, String decryptedFile) {
        try (BufferedInputStream bis = new BufferedInputStream(new FileInputStream(encryptedFile));
             BufferedOutputStream bos = new BufferedOutputStream(new FileOutputStream(decryptedFile))) {
            byte[] buffer = new byte[8];
            int bytesRead;

            while ((bytesRead = bis.read(buffer)) != -1) {
                long encryptedData = convertBytesToLong(buffer, bytesRead);
                long decryptedData = decryption64(encryptedData);
                byte[] decryptedBuffer = convertLongToBytes(decryptedData);
                bos.write(decryptedBuffer);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        if (decryptedFile.contains("txt")) {
            FileProcessor.processFile(decryptedFile);
            new File(decryptedFile).delete();
            new File("tmp").renameTo(new File(decryptedFile));
        }

    }

    private static long convertBytesToLong(byte[] bytes, int length) {
        long result = 0;
        for (int i = 0; i < length; i++) {
            result = (result << 8) | (bytes[i] & 0xFF);
        }
        return result;
    }

    private static byte[] convertLongToBytes(long value) {
        byte[] bytes = new byte[8];
        for (int i = 7; i >= 0; i--) {
            bytes[i] = (byte) (value & 0xFF);
            value >>= 8;
        }
        return bytes;
    }

    // public String encrption(String data) {
    //     String content = null;
    //     try {
    //         String tempFilePath = "tmp";
    //         FileWriter fileWriter = new FileWriter(tempFilePath);
    //         BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
    //         bufferedWriter.write(data);
    //         bufferedWriter.close();
    //         System.out.println("Text has been written to the temporary file: " + tempFilePath);
    //         encryptFile("tmp", "entmp");
           
    //         content = Files.readString(Paths.get("entmp"));
            
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    //     return content;
    // }

    // public String decrption(String data) {
    //     String content = null;
    //     try {
    //         String tempFilePath = "tmp";
    //         FileWriter fileWriter = new FileWriter(tempFilePath);
    //         BufferedWriter bufferedWriter = new BufferedWriter(fileWriter);
    //         bufferedWriter.write(data);
    //         bufferedWriter.close();
    //         decryptFile("tmp", "entmp");
           
    //         content = Files.readString(Paths.get("entmp"));
            
    //     } catch (IOException e) {
    //         e.printStackTrace();
    //     }
    //     return content;
    // }
}


class FileProcessor {

    public static void processFile(String filePath) {
        File file = new File(filePath);
        removeNonPrintableChars(file, "tmp");
    }
    private static boolean isControlChar(byte b) {
        return b == '\n' || b == '\r' || b == '\t';
    }

    private static void removeNonPrintableChars(File inputFile, String outputFilePath) {
        try (BufferedReader reader = new BufferedReader(new FileReader(inputFile));
             BufferedWriter writer = new BufferedWriter(new FileWriter(outputFilePath))) {

            String line;
            while ((line = reader.readLine()) != null) {
                String printableLine = removeNonPrintableCharsFromLine(line);
                writer.write(printableLine);
                writer.newLine();
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private static String removeNonPrintableCharsFromLine(String line) {
        StringBuilder printableLine = new StringBuilder();

        for (int i = 0; i < line.length(); i++) {
            char c = line.charAt(i);
            if (c >= 32 || isControlChar((byte) c)) {
                printableLine.append(c);
            }
        }

        return printableLine.toString();
    }

    
}
