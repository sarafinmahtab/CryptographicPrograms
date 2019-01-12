import java.util.Scanner;

public class Main {

    public static void main(String[] args) {
        try {

            String path = "/home/mahtab/Courses/Security/Lab 6/";

            System.out.println("Enter any message to apply");
            Scanner scanner = new Scanner(System.in);
            String message = scanner.nextLine();


            /* Task 1*/
            /* AES Encryption with 2 modes and 2 key lengths */
            System.out.println("Enter key length (16 or 32 bits) to apply AES encryption");
            String bits = scanner.nextLine();

            System.out.println("Enter mode (CBC or ECB) to apply AES encryption");
            String mode = scanner.nextLine();


            switch (mode) {
                case "CBC":
                    new CBC(message, Integer.parseInt(bits), path);
                    break;
                case "ECB":
                    new ECB(message, Integer.parseInt(bits), path);
                    break;
                default:
                    System.out.println("Mode not matched. Only enter CBC or ECB");
                    break;
            }


            /* Task 2 and 3 */
            /* RSA Encryption and Signature Verification */
            new RSA(message, path);



            /* Task 4 */
            /* SHA 256 Hashing */
            new SHA256Hashing(message);


        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
