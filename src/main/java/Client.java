import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import java.util.Scanner;
import javax.crypto.spec.SecretKeySpec;

public class Client {
    public static void main(String[] args) {
        try (Socket socket = new Socket("localhost", 12345)) {
            System.out.println("Connected to server.");

            //username
            // Scanner Userscanner = new Scanner(System.in);
            // System.out.print("Enter your username: ");
            // String username = Userscanner.nextLine();

            DataInputStream input = new DataInputStream(socket.getInputStream());
            DataOutputStream output = new DataOutputStream(socket.getOutputStream());

            // output.writeUTF(username);
            // output.flush();
            // System.out.println("Username sent to server.");

            // --- Key exchange ---
            KeyPair clientKeyPair = CryptoUtils.generateKeyPair();
            PublicKey clientPublicKey = clientKeyPair.getPublic();

            String serverPublicKeyEncoded = input.readUTF();
            byte[] decodedKey = Base64.getDecoder().decode(serverPublicKeyEncoded);
            PublicKey serverPublicKey = CryptoUtils.decodePublicKey(decodedKey);

            String clientPublicKeyEncoded = Base64.getEncoder().encodeToString(clientPublicKey.getEncoded());
            output.writeUTF(clientPublicKeyEncoded);
            output.flush();

            byte[] sharedSecret = CryptoUtils.generateSharedSecret(clientKeyPair.getPrivate(), serverPublicKey);
            SecretKeySpec aesKey = CryptoUtils.AESKey(sharedSecret);
            System.out.println("Secure channel established.");

            // Start a background thread to listen for messages
            Thread listener = new Thread(() -> {
                try {
                    while (true) {
                        String encryptedMsg = input.readUTF();
                        System.out.println("[DEBUG] Encrypted message from server: " + encryptedMsg);
                        String decrypted = new String(CryptoUtils.decryptAES(encryptedMsg, aesKey));
                        System.out.println("[Server/Chat] " + decrypted);

                    }
                } catch (Exception e) {
                    System.out.println("Disconnected from server.");
                }
            });
            listener.start();

            // User input loop
            Scanner scanner = new Scanner(System.in);
            while (true) {
                System.out.print("You: ");
                String message = scanner.nextLine();
                if ("exit".equalsIgnoreCase(message)) {
                    break;
                }
                String encrypted = CryptoUtils.encryptAES(message.getBytes(), aesKey);
                output.writeUTF(encrypted);
                output.flush();
            }
            scanner.close();
            //Userscanner.close();

        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    // Method to reset the chat
    private static void resetChat(DataOutputStream output) {
        try {
            // Notify the server about the reset
            output.writeUTF("/reset");
            output.flush();
            System.out.println("Chat has been reset.");
        } catch (IOException e) {
            System.err.println("Failed to reset chat: " + e.getMessage());
        }
    }
}
