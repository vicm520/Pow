import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

public class Pow {
    public static void main(String[] args) throws Exception {
        String nickname = args.length > 0 ? args[0] : "chumeng";

        Result fourZeros = mine(nickname, 4);
        System.out.println("==== 满足 4 个 0 开头的Hash结果 ====");
        System.out.println("Time(ms): " + fourZeros.elapsedMillis);
        System.out.println("Content : " + fourZeros.content);
        System.out.println("Hash    : " + fourZeros.hashHex);

        Result fiveZeros = mine(nickname, 5);
        System.out.println("==== 满足 5 个 0 开头的Hash结果 ====");
        System.out.println("Time(ms): " + fiveZeros.elapsedMillis);
        System.out.println("Content : " + fiveZeros.content);
        System.out.println("Hash    : " + fiveZeros.hashHex);
    }

    private static Result mine(String nickname, int leadingZeros) throws NoSuchAlgorithmException {
        String targetPrefix = repeatChar('0', leadingZeros);
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        long start = System.nanoTime();

        long nonce = 0L;
        while (true) {
            String content = nickname + String.valueOf(nonce);
            byte[] hash = digest.digest(content.getBytes(StandardCharsets.UTF_8));
            String hex = toHex(hash);
            if (hex.startsWith(targetPrefix)) {
                long end = System.nanoTime();
                long ms = (end - start) / 1_000_000L;
                return new Result(content, hex, ms);
            }
            nonce++;
        }
    }

    private static String repeatChar(char ch, int count) {
        if (count <= 0) return "";
        StringBuilder sb = new StringBuilder(count);
        for (int i = 0; i < count; i++) sb.append(ch);
        return sb.toString();
    }

    private static String toHex(byte[] bytes) {
        char[] hexArray = "0123456789abcdef".toCharArray();
        char[] hexChars = new char[bytes.length * 2];
        for (int j = 0; j < bytes.length; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = hexArray[v >>> 4];
            hexChars[j * 2 + 1] = hexArray[v & 0x0F];
        }
        return new String(hexChars);
    }

    private static class Result {
        final String content;
        final String hashHex;
        final long elapsedMillis;

        Result(String content, String hashHex, long elapsedMillis) {
            this.content = content;
            this.hashHex = hashHex;
            this.elapsedMillis = elapsedMillis;
        }
    }
}


