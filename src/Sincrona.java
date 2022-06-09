import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.Base64;

public class Sincrona {
    private static final String algorithm = "AES";
    private static Cipher cipher;
    private static MessageDigest messageDigest;
    private static Base64.Decoder decoder = Base64.getDecoder();
    private static Base64.Encoder encoder = Base64.getEncoder();

    private static SecretKey getSecretKey(String key) {
        byte[] keyBytes = messageDigest.digest(key.getBytes());
        return new SecretKeySpec(keyBytes, algorithm);
    }

    private static String encrypt(String key, String message) throws Exception {
        SecretKey secretKey = getSecretKey(key);
        cipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return encoder.encodeToString(encryptedBytes);
    }

    private static String decrypt(String key, String cipherText) throws Exception {
        SecretKey secretKey = getSecretKey(key);
        cipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = decoder.decode(cipherText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        cipher = Cipher.getInstance(algorithm);
        messageDigest = MessageDigest.getInstance("SHA-256");

        String key = "swordfish";
        String message = "Hola";
        String encrypted = encrypt(key, message);
        System.out.println("El mensaje cifrado es: " + encrypted);
        String decypted = decrypt(key, encrypted);
        System.out.println("El mensaje descifrado es: " + decypted);
    }

}