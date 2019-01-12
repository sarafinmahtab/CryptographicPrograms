import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.Cipher;

import static java.nio.charset.StandardCharsets.UTF_8;

public class RSA {

    private PublicKey pubKey;
    private PrivateKey privateKey;

    private String path;

    private String rsaKeyFileName = "rsa_key.txt";
    private String rsaSignatureFileName = "rsa_signature.txt";

    private String message;

    RSA(String message, String path) throws Exception {

        this.message = message;
        this.path = path;

        // generate public and private keys
        KeyPair keyPair = buildKeyPair();
        pubKey = keyPair.getPublic();
        privateKey = keyPair.getPrivate();



        // encrypt the message
        byte[] encrypted = encrypt(privateKey, message);
        System.out.println("RSA Encrypted message: " + new String(encrypted) + "\n");

        writeToFile(encrypted, rsaKeyFileName);

        // decrypt the message taking from file
        encrypted = readFromFile(rsaKeyFileName);

        byte[] decrypted = decrypt(pubKey, encrypted);
        System.out.println("RSA Decrypted message: " + new String(decrypted) + "\n");



        // signing message
        String signature = sign(privateKey, message);
        System.out.println("Signature: " + signature + "\n");
        writeToFile(signature.getBytes(), rsaSignatureFileName);

        // verify signature
        byte[] signatureBytes = readFromFile(rsaSignatureFileName);
        boolean verified = verify(new String(signatureBytes), message, pubKey);

        System.out.println("Signature Verification: " + verified + "\n");
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

    private static KeyPair buildKeyPair() throws NoSuchAlgorithmException {
        final int keySize = 2048;
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(keySize);
        return keyPairGenerator.genKeyPair();
    }

    private static byte[] encrypt(PrivateKey privateKey, String message) throws Exception {

        long startTime = System.nanoTime();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, privateKey);

        byte[] bytes = cipher.doFinal(message.getBytes());

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (RSA Decryption): " + duration/1000);

        return bytes;
    }

    private static byte[] decrypt(PublicKey publicKey, byte[] encrypted) throws Exception {

        long startTime = System.nanoTime();

        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, publicKey);

        byte[] bytes = cipher.doFinal(encrypted);

        long endTime = System.nanoTime();
        long duration = (endTime - startTime);
        System.out.println("Execution Time (RSA Decryption): " + duration/1000);

        return cipher.doFinal(encrypted);
    }

    private String sign(PrivateKey privateKey, String message) throws Exception {
        Signature privateSignature = Signature.getInstance("SHA256withRSA");
        privateSignature.initSign(privateKey);
        privateSignature.update(message.getBytes(UTF_8));

        byte[] signature = privateSignature.sign();

        return Base64.getEncoder().encodeToString(signature);
    }

    public boolean verify(String signature, String message, PublicKey publicKey) throws Exception {
        Signature publicSignature = Signature.getInstance("SHA256withRSA");
        publicSignature.initVerify(publicKey);
        publicSignature.update(message.getBytes(UTF_8));

        byte[] signatureBytes = Base64.getDecoder().decode(signature);

        return publicSignature.verify(signatureBytes);
    }

    public PublicKey getPubKey() {
        return pubKey;
    }

    public void setPubKey(PublicKey pubKey) {
        this.pubKey = pubKey;
    }

    public PrivateKey getPrivateKey() {
        return privateKey;
    }

    public void setPrivateKey(PrivateKey privateKey) {
        this.privateKey = privateKey;
    }
}

/*

RSA Encryption and Decryption Source: https://gist.github.com/dmydlarz/32c58f537bb7e0ab9ebf
RSA Signature Source: https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
Read and write Source:
i) http://www.mkyong.com/java/how-to-convert-file-into-an-array-of-bytes/
ii) https://www.mkyong.com/java/how-to-convert-array-of-bytes-into-file/

 */
