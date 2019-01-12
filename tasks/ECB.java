import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

class ECB {

    private String algorithom;
    private String input;
    private String secretKey;
    private String path;

    private String ecbKeyFileName = "ecb_key.txt";

    ECB(String input, int bits, String path) throws IOException {

        this.algorithom = "AES";

        this.input = input;
        this.secretKey = generateRandomKey(bits);
        this.path = path;

        String encryptedValue = encrypt();

        System.out.println("Original Text: " + input + "\n");

        System.out.println("AES encrypted value (ECB Mode): " + encryptedValue + "\n");

        encryptedValue = Base64.getEncoder().encodeToString(readFromFile(ecbKeyFileName));

        System.out.println("AES decrypted value (ECB Mode): " + decrypt(encryptedValue) + "\n");
    }

    private String encrypt() throws IOException {

        long startTime = System.nanoTime();

        byte[] crypted = null;
        try {

            SecretKeySpec skey = new SecretKeySpec(secretKey.getBytes(), algorithom);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.ENCRYPT_MODE, skey);
            crypted = cipher.doFinal(input.getBytes());
        } catch (Exception e) {
            System.out.println(e.toString());
        }

        writeToFile(crypted, ecbKeyFileName);

        Base64.Encoder encoder = Base64.getEncoder();
        String encrypt = encoder.encodeToString(crypted);

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (ECB Encryption): " + duration/1000);

        return encrypt;
    }

    private String decrypt(String encryptedValue) {

        long startTime = System.nanoTime();

        byte[] output = null;
        try {
            java.util.Base64.Decoder decoder = java.util.Base64.getDecoder();

            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), algorithom);

            Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
            cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);
            output = cipher.doFinal(decoder.decode(encryptedValue));
        } catch (Exception e) {
            System.out.println(e.toString());
        }

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (ECB Decryption): " + duration/1000);

        return new String(output);
    }

    // function to generate a random string of length n
    private String generateRandomKey(int n) {

        // chose a Character random from this String
        String AlphaNumericString = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                + "0123456789"
                + "abcdefghijklmnopqrstuvxyz";

        // create StringBuffer size of AlphaNumericString
        StringBuilder sb = new StringBuilder(n);

        for (int i = 0; i < n; i++) {

            // generate a random number between
            // 0 to AlphaNumericString variable length
            int index
                    = (int) (AlphaNumericString.length()
                    * Math.random());

            // add Character one by one in end of sb
            sb.append(AlphaNumericString
                    .charAt(index));
        }

        return sb.toString();
    }



    private byte[] readFromFile(String fileName) throws IOException {
        // pass the path to the file as a parameter

        return Files.readAllBytes(Paths.get(path + fileName));
    }

    private void writeToFile(byte[] key, String fileName) throws IOException {

        File file = new File(path + fileName);

        if (file.delete()) {

        }

        Path pathV = Paths.get(path + fileName);
        Files.write(pathV, key);
    }
}

/*
https://gist.github.com/netkiller/8167ff2397320c38c946?fbclid=IwAR3wk_P8DzpWYbBYDFfo5kognq6pRuR4qOdcNN09AnuzZ3RINcSpZ76ixVs
 */
