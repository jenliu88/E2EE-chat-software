import java.io.*;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PublicKey;
import java.util.Base64;
import javax.crypto.spec.SecretKeySpec;

public class ClientHandler implements Runnable {
    private Socket socket;
    private DataInputStream input;
    private DataOutputStream output;
    private SecretKeySpec aesKey;

    public ClientHandler(Socket socket) {
        this.socket = socket;
    }

    @Override
    public void run() {
        try {
            input = new DataInputStream(socket.getInputStream());
            output = new DataOutputStream(socket.getOutputStream());

            // --- Key exchange ---
            KeyPair serverKeyPair = CryptoUtils.generateKeyPair();
            PublicKey serverPublicKey = serverKeyPair.getPublic();
            output.writeUTF(Base64.getEncoder().encodeToString(serverPublicKey.getEncoded()));
            output.flush();

            String clientPublicKeyEncoded = input.readUTF();
            byte[] decodedKey = Base64.getDecoder().decode(clientPublicKeyEncoded);
            PublicKey clientPublicKey = CryptoUtils.decodePublicKey(decodedKey);

            byte[] sharedSecret = CryptoUtils.generateSharedSecret(serverKeyPair.getPrivate(), clientPublicKey);
            aesKey = CryptoUtils.AESKey(sharedSecret);

            // Send chat history
            synchronized (Server.chatHistory) {
                for (String msg : Server.chatHistory) {
                    sendMessage(msg);
                }
            }

            // --- Communication loop ---
            while (true) {
                // Read encrypted message from the client
                String encryptedMsg = input.readUTF();
                
                // Log the raw encrypted data
                System.out.println("Encrypted message from client: " + encryptedMsg);

                // Decrypt it for broadcasting (server doesn't need plaintext, but we do for now)
                String decrypted = new String(CryptoUtils.decryptAES(encryptedMsg, aesKey));

                // Store and broadcast the plaintext to other clients
                Server.addMessage(decrypted);
                Server.broadcast(decrypted, this);
            }

        } catch (Exception e) {
            System.out.println("Client disconnected.");
        } finally {
            try { socket.close(); } catch (IOException ignored) {}
            Server.clients.remove(this);
        }
    }

    // Send encrypted message to this client
    public void sendMessage(String message) {
        try {
            String encrypted = CryptoUtils.encryptAES(message.getBytes(), aesKey);
            output.writeUTF(encrypted);
            output.flush();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
