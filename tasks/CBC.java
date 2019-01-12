import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Base64;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

class CBC {

    private String algorithom;
    private String path;

    private String cbcKeyFileName = "cbc_key.txt";

    CBC(String input, int bits, String path) throws Exception {

        if (bits == 16) {
            bits = 128;
        } else if (bits == 24) {
            bits = 192;
        } else if (bits == 32) {
            bits = 256;
        }

        this.algorithom = "AES";
        this.path = path;

        KeyGenerator keyGenerator = KeyGenerator.getInstance(algorithom);
        keyGenerator.init(bits);


        // Generate Key
        SecretKey key = keyGenerator.generateKey();

        // Generating IV.
        byte[] IV = new byte[16];
        SecureRandom random = new SecureRandom();
        random.nextBytes(IV);

        System.out.println("Original Text: " + input + "\n");

        byte[] cipherText = encrypt(input.getBytes(),key, IV);
        System.out.println("AES encrypted value (CBC Mode): "
                + Base64.getEncoder().encodeToString(cipherText) + "\n");

        writeToFile(cipherText, cbcKeyFileName);

        cipherText = readFromFile(cbcKeyFileName);

        String decryptedText = decrypt(cipherText, key, IV);
        System.out.println("AES decrypted value (CBC Mode): " + decryptedText + "\n");
    }

    private byte[] encrypt(byte[] plaintext, SecretKey key, byte[] IV) throws Exception {

        long startTime = System.nanoTime();

        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), algorithom);

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for ENCRYPT_MODE
        cipher.init(Cipher.ENCRYPT_MODE, keySpec, ivSpec);

        byte[] bytes = cipher.doFinal(plaintext);

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (CBC Encryption): " + duration/1000);

        //Perform Encryption
        return bytes;
    }

    private String decrypt(byte[] cipherText, SecretKey key, byte[] IV) throws Exception {

        long startTime = System.nanoTime();

        //Get Cipher Instance
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");

        //Create SecretKeySpec
        SecretKeySpec keySpec = new SecretKeySpec(key.getEncoded(), algorithom);

        //Create IvParameterSpec
        IvParameterSpec ivSpec = new IvParameterSpec(IV);

        //Initialize Cipher for DECRYPT_MODE
        cipher.init(Cipher.DECRYPT_MODE, keySpec, ivSpec);

        //Perform Decryption
        byte[] decryptedText = cipher.doFinal(cipherText);


        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (CBC Decryption): " + duration/1000);


        return new String(decryptedText);
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
