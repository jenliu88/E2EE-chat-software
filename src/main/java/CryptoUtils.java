import org.bouncycastle.jce.provider.BouncyCastleProvider;
import javax.crypto.Cipher;
import javax.crypto.KeyAgreement;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.security.*;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;

public class CryptoUtils {
    //Bouncy Castle provider
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    //Generate keypair
    public static KeyPair generateKeyPair() throws Exception {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("X25519", "BC");
        return keyGen.generateKeyPair();
    }

    //Generate shared seceret
    public static byte[] generateSharedSecret(PrivateKey privateKey, PublicKey publicKey) throws Exception {
        KeyAgreement keyAgreement = KeyAgreement.getInstance("X25519", "BC");
        keyAgreement.init(privateKey);
        keyAgreement.doPhase(publicKey, true);
        return keyAgreement.generateSecret();
    }

    //AES key from shared secret 
    public static SecretKeySpec AESKey(byte[] sharedSecret) throws Exception {
        // Hash the shared secret using SHA-256
        MessageDigest sha256 = MessageDigest.getInstance("SHA-256");
        byte[] hash = sha256.digest(sharedSecret);

        // Use the first 16 bytes of the hash as the AES key
        return new SecretKeySpec(hash, 0, 16, "AES");
    }

    //Encrypt data with AES
     // Encrypt data using AES-GCM
     public static String encryptAES(byte[] plaintext, SecretKeySpec aesKey) throws Exception {
        // Create a Cipher instance for AES in GCM mode with no padding
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Generate a random 12-byte IV (Initialization Vector) for GCM
        byte[] iv = new byte[12];
        SecureRandom random = new SecureRandom();
        random.nextBytes(iv);

        // Configure GCM with a 128-bit authentication tag
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // Initialize the cipher in encryption mode with the AES key and IV
        cipher.init(Cipher.ENCRYPT_MODE, aesKey, gcmSpec);

        // Perform encryption
        byte[] ciphertext = cipher.doFinal(plaintext);

        // Combine the IV and ciphertext into a single byte array
        byte[] encryptedData = new byte[iv.length + ciphertext.length];
        System.arraycopy(iv, 0, encryptedData, 0, iv.length); // Copy IV to the beginning
        System.arraycopy(ciphertext, 0, encryptedData, iv.length, ciphertext.length); // Append ciphertext

        // Encode the combined IV and ciphertext as a Base64 string
        return Base64.getEncoder().encodeToString(encryptedData);
    }

    // Decrypt data using AES-GCM
    public static byte[] decryptAES(String encryptedData, SecretKeySpec aesKey) throws Exception {
        // Decode the Base64-encoded string into a byte array
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);

        // Extract the 12-byte IV from the beginning of the decoded data
        byte[] iv = new byte[12];
        System.arraycopy(decodedData, 0, iv, 0, iv.length);

        // Configure GCM with the extracted IV and a 128-bit authentication tag
        GCMParameterSpec gcmSpec = new GCMParameterSpec(128, iv);

        // Create a Cipher instance for AES in GCM mode with no padding
        Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding", "BC");

        // Initialize the cipher in decryption mode with the AES key and IV
        cipher.init(Cipher.DECRYPT_MODE, aesKey, gcmSpec);

        // Perform decryption (excluding the IV from the input data)
        return cipher.doFinal(decodedData, iv.length, decodedData.length - iv.length);
    }


    public static PublicKey decodePublicKey(byte[] encodedKey) throws Exception {
        KeyFactory keyFactory = KeyFactory.getInstance("X25519");
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        return keyFactory.generatePublic(keySpec);
    }
    //testing get rid of this later - this verifies that the decoding is working 
    public static void main(String[] args) {
        try {
            // Test KeyPair generation
            KeyPair keyPair = CryptoUtils.generateKeyPair();
            if (keyPair == null || keyPair.getPrivate() == null || keyPair.getPublic() == null) {
                throw new Exception("KeyPair generation failed!");
            }
            System.out.println("KeyPair generation successful!");

            // Test shared secret generation
            KeyPair keyPair1 = CryptoUtils.generateKeyPair();
            KeyPair keyPair2 = CryptoUtils.generateKeyPair();
            byte[] sharedSecret1 = CryptoUtils.generateSharedSecret(keyPair1.getPrivate(), keyPair2.getPublic());
            byte[] sharedSecret2 = CryptoUtils.generateSharedSecret(keyPair2.getPrivate(), keyPair1.getPublic());
            if (!Arrays.equals(sharedSecret1, sharedSecret2)) {
                throw new Exception("Shared secret generation failed!");
            }
            System.out.println("Shared secret generation successful!");

            // Test AES key derivation
            SecretKeySpec aesKey = CryptoUtils.AESKey(sharedSecret1);
            if (aesKey == null || aesKey.getEncoded().length != 16) {
                throw new Exception("AES key derivation failed!");
            }
            System.out.println("AES key derivation successful!");

            // Test AES encryption and decryption
            String plaintext = "Hello, secure world!";
            String encryptedData = CryptoUtils.encryptAES(plaintext.getBytes(), aesKey);
            byte[] decryptedData = CryptoUtils.decryptAES(encryptedData, aesKey);
            if (!plaintext.equals(new String(decryptedData))) {
                throw new Exception("AES encryption/decryption failed!");
            }
            System.out.println("AES encryption and decryption successful!");

            // Test public key decoding
            byte[] encodedPublicKey = keyPair1.getPublic().getEncoded();
            if (!keyPair1.getPublic().equals(CryptoUtils.decodePublicKey(encodedPublicKey))) {
                throw new Exception("Public key decoding failed!");
            }
            System.out.println("Public key decoding successful!");

        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}