import java.util.ArrayList;
import java.util.List;

public class Challenge1_1 {
    // Ciphertext från challenge 1.1
    private static final String CIPHERTEXT = "D_AZ_5H7S006_9WHF6BHD_33HX_5VHSAH3WS0AHIJHX3SY0H064WH6XHAZW4HS9WHX_3WH5S4WVHX3SYH5HTBAH064WA_4W0HAZWHX3SYH_0HZ_VVW5H_5HS56AZW9HX_3WHAZ_0H4W00SYWH_0HAZWHS50DW9HA6HUZS33W5YWHIHV6AHI";

    // Definiera alfabetet som används i ciphern
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ_1234567890";
    private static final int N = ALPHABET.length();

    public static void main(String[] args) {
        // Generera alla möjliga plaintexts och filtrera ut läsbara texter
        List<Result> readable = new ArrayList<>();

        for (int key = 1; key < N; key++) {
            String plaintext = decrypt(CIPHERTEXT, key);
            if (containsAny(plaintext, "THE", "AND", "YOU")) {
                readable.add(new Result(key, plaintext));
            }
        }

        // Printa resultat
        for (Result result : readable) {
            System.out.println(result.key + ": " + result.plaintext);
        }
    }

    // Funktion för att dekryptera med en given nyckel
    private static String decrypt(String ciphertext, int key) {
        StringBuilder plaintext = new StringBuilder();

        for (char c : ciphertext.toCharArray()) {
            int index = ALPHABET.indexOf(c);
            int newIndex = (index + key) % N;
            plaintext.append(ALPHABET.charAt(newIndex));
        }

        return plaintext.toString().replace('_', ' ');
    }

    // Hjälpmetod för att kolla om plaintext innehåller något av orden
    private static boolean containsAny(String text, String... words) {
        for (String word : words) {
            if (text.contains(word)) {
                return true;
            }
        }
        return false;
    }

    // Hjälpklass för att hålla nyckel och plaintext
    private static class Result {
        int key;
        String plaintext;

        Result(int key, String plaintext) {
            this.key = key;
            this.plaintext = plaintext;
        }
    }
}
