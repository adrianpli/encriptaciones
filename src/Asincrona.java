import javax.crypto.Cipher;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

public class Asincrona {
    private static final String algorithm = "RSA";
    private static Cipher cipher;
    private static KeyFactory keyFactory;
    private static Base64.Decoder decoder = Base64.getDecoder();
    private static Base64.Encoder encoder = Base64.getEncoder();

    private static PublicKey getPublicKey(String publicKey) throws Exception {
        String publicKeyAsPEM = publicKey.replace("-----BEGIN PUBLIC KEY-----", "");
        publicKeyAsPEM = publicKeyAsPEM.replace("-----END PUBLIC KEY-----", "");
        publicKeyAsPEM = publicKeyAsPEM.replace("\n", "");
        byte[] publicKeyBytes = decoder.decode(publicKeyAsPEM);
        X509EncodedKeySpec x509EncodedKeySpec = new X509EncodedKeySpec(publicKeyBytes);
        return keyFactory.generatePublic(x509EncodedKeySpec);
    }

    private static PrivateKey getPrivateKey(String privateKey) throws Exception {
        String privateKeyAsPEM = privateKey.replace("-----BEGIN PRIVATE KEY-----", "");
        privateKeyAsPEM = privateKeyAsPEM.replace("-----END PRIVATE KEY-----", "");
        privateKeyAsPEM = privateKeyAsPEM.replace("\n", "");
        byte[] privateKeyBytes = decoder.decode(privateKeyAsPEM);
        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
        return keyFactory.generatePrivate(pkcs8EncodedKeySpec);
    }

    private static String encrypt(String publicKeyAsString, String message) throws Exception {
        PublicKey publicKey = getPublicKey(publicKeyAsString);
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return encoder.encodeToString(encryptedBytes);
    }

    private static String decrypt(String privateKeyAsString, String cipherText) throws Exception {
        PrivateKey privateKey = getPrivateKey(privateKeyAsString);
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] encryptedBytes = decoder.decode(cipherText);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);
        return new String(decryptedBytes, StandardCharsets.UTF_8);
    }
    public static void main(String[] args) throws Exception {
        cipher = Cipher.getInstance(algorithm);
        keyFactory = KeyFactory.getInstance(algorithm);

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
        String message = "minecfat";
        String encrypted = encrypt(publicKey, message);
        System.out.println("El mensaje cifrado es: " + encrypted);
        String decrypted = decrypt(privateKey, encrypted);
        System.out.println("El mensaje descifrado es: " + decrypted);
    }
}