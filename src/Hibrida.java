import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Hibrida {
    private static final String rsaAlgorithm = "RSA";
    private static final String aesAlgorithm = "AES";
    private static Cipher rsaCipher, aesCipher;
    private static MessageDigest messageDigest;
    private static KeyFactory rsaKeyFactory;
    private static Base64.Decoder decoder = Base64.getDecoder();
    private static Base64.Encoder encoder = Base64.getEncoder();

    private static PublicKey getPublicKey(String publicKey) throws Exception {
        String publicKeyAsPEM = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyAsPEM = publicKeyAsPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyAsPEM = publicKeyAsPEM.replace("\n", "");
        byte[] publicKeyBytes = decoder.decode(publicKeyAsPEM);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return rsaKeyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        String privateKeyAsPEM = privateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        privateKeyAsPEM = privateKeyAsPEM.replace("-----END PRIVATE KEY-----", "");
        privateKeyAsPEM = privateKeyAsPEM.replace("\n", "");
        byte[] privateKeyBytes = decoder.decode(privateKeyAsPEM);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return rsaKeyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    private static String publicEncrypt(String publicKeyAsString, String message) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyAsString);
        rsaCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = rsaCipher.doFinal(message.getBytes());
        return encoder.encodeToString(encryptedBytes);
    }

    private static String privateDecrypt(String privateKeyAsString, String cipherText) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyAsString);
        rsaCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = decoder.decode(cipherText);
        byte[] decryptedBytes = rsaCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }

    private static SecretKey getSecretKey(String key) {
        byte[] keyBytes = messageDigest.digest(key.getBytes());
        return new SecretKeySpec(keyBytes, aesAlgorithm);
    }

    private static String aesEncrypt(String key, String message) throws Exception {
        SecretKey secretKey = getSecretKey(key);
        aesCipher.init(Cipher.ENCRYPT_MODE, secretKey);
        byte[] encryptedBytes = aesCipher.doFinal(message.getBytes());
        return encoder.encodeToString(encryptedBytes);
    }

    private static String aesDecrypt(String key, String cipherText) throws Exception {
        SecretKey secretKey = getSecretKey(key);
        aesCipher.init(Cipher.DECRYPT_MODE, secretKey);
        byte[] encryptedBytes = decoder.decode(cipherText);
        byte[] decryptedBytes = aesCipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }


    private static String getRandomString() {
        String allowedChars = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
        StringBuilder builder = new StringBuilder();
        int limit = 32;
        while (limit-- != 0) {
            int character = (int) (Math.random() * allowedChars.length());
            builder.append(allowedChars.charAt(character));
        }
        return builder.toString();
    }

    public static void main(String[] args) throws Exception {
        rsaCipher = Cipher.getInstance(rsaAlgorithm);
        aesCipher = Cipher.getInstance(aesAlgorithm);
        rsaKeyFactory = KeyFactory.getInstance(rsaAlgorithm);
        messageDigest = MessageDigest.getInstance("SHA-256");

        String publicKey = "-----BEGIN PUBLIC KEY-----\n" +
                "MFwwDQYJKoZIhvcNAQEBBQADSwAwSAJBAJIuQ+SfRUai7fizF6xciZJWV825w/RO\n" +
                "wWO7dDqrZXCqoiRNnJXIX+VVxe6qLrQz/k8E0ShPFolkVtcyy7/zHdsCAwEAAQ==\n" +
                "-----END PUBLIC KEY-----";
        String privateKey = "-----BEGIN PRIVATE KEY-----\n" +
                "MIIBVQIBADANBgkqhkiG9w0BAQEFAASCAT8wggE7AgEAAkEAki5D5J9FRqLt+LMX\n" +
                "rFyJklZXzbnD9E7BY7t0OqtlcKqiJE2clchf5VXF7qoutDP+TwTRKE8WiWRW1zLL\n" +
                "v/Md2wIDAQABAkBVi++9jpvLD7R2U9Cp1OnJkvAFfA46HhC83cnSP9W4jahxqGps\n" +
                "bWWYaUN2LoK/E2dv8O5FLVKcXJZXDuozN6dxAiEA/TxPD/qhFJKQbPlnlij1/E8B\n" +
                "9PYzBP3RPvHrwqwFfXMCIQCTxsgCNFJ5PaVeg+UYYhWMVyRcF3CRE6V/c4585F1D\n" +
                "+QIgWtq9XvVDv5bJ/F8K3CP8BTbvc8y1B1BtN1Eijeib26MCIQCKLpykAw0DtfNG\n" +
                "mArHbCA+JNYpDvoBjt94eDPK8TeM8QIhAOSsqbydb3Y31ViC788SWkV6LgUR/7QV\n" +
                "tUUCtWxYjLzu\n" +
                "-----END PRIVATE KEY-----";

        String sessionKey = getRandomString();
        String message = "Hola a todos";
        String encryptedSessionKey = publicEncrypt(publicKey, sessionKey);
        String encryptedMessage = aesEncrypt(sessionKey, message);

        System.out.println("La llave de sesion cifrada es: " + encryptedSessionKey);
        System.out.println("El mensaje cifrado es: " + encryptedMessage);

        String decryptedSessionKey = privateDecrypt(privateKey, encryptedSessionKey);
        String decryptedMessage = aesDecrypt(decryptedSessionKey, encryptedMessage);
        System.out.println("El mensaje descifrado es: " + decryptedMessage);
    }
}