package cc.weno.ca;
import org.apache.commons.codec.binary.Base64;

import javax.crypto.Cipher;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class SignService {

    /**
     * RSA 算法
     **/
    private static final String ALGORITHM_RSA = "RSA";

    /**
     * 签名算法
     **/
    private static final String ALGORITHM_SIGNATURE = "SHA1WithRSA";

    /**
     * Cipher类提供了加密和解密的功能
     * <p>
     * Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1PADDING");
     * RSA是算法，ECB是分块模式，PKCS1Padding是填充模式，整个构成一个完整的加密算法
     *
     * <pre>
     * 有以下的参数：
     * * AES/CBC/NoPadding (128)
     * * AES/CBC/PKCS5Padding (128)
     * * AES/ECB/NoPadding (128)
     * * AES/ECB/PKCS5Padding (128)
     * * DES/CBC/NoPadding (56)
     * * DES/CBC/PKCS5Padding (56)
     * * DES/ECB/NoPadding (56)
     * * DES/ECB/PKCS5Padding (56)
     * * DESede/CBC/NoPadding (168)
     * * DESede/CBC/PKCS5Padding (168)
     * * DESede/ECB/NoPadding (168)
     * * DESede/ECB/PKCS5Padding (168)
     * * RSA/ECB/PKCS1Padding (1024, 2048)
     * * RSA/ECB/OAEPWithSHA-1AndMGF1Padding (1024, 2048)
     * * RSA/ECB/OAEPWithSHA-256AndMGF1Padding (1024, 2048)
     * </pre>
     */
    private static final String PADDING = "RSA/ECB/PKCS1PADDING";

    /**
     * 生成非对称密钥对，默认使用RSA
     *
     * @return
     * @throws Exception
     */
    public static String[] generateRSAKeyPair() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance(ALGORITHM_RSA);
        keyPairGenerator.initialize(2048);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();

        PublicKey publicKey = keyPair.getPublic();
        PrivateKey privateKey = keyPair.getPrivate();

        String publicKeyStr = Base64.encodeBase64String(publicKey.getEncoded());
        String privateKeyStr = Base64.encodeBase64String(privateKey.getEncoded());
        return new String[]{publicKeyStr, privateKeyStr};
    }

    /**
     * 使用数据接收方的公钥加密
     *
     * @param publicKeyStr BASE64编码格式的公钥
     * @param data         待加密数据
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKeyStr(String publicKeyStr, String data) throws Exception {
        PublicKey publicKey = getPublicKeyFromString(publicKeyStr);
        byte[] bytes = doCipher(Cipher.ENCRYPT_MODE, publicKey, data.getBytes());
        return Base64.encodeBase64String(bytes);
    }

    /**
     * 数据接收方使用自己的私钥解密
     *
     * @param privateKeyStr BASE64编码格式的私钥
     * @param encryptedData 待解密数据
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKeyStr(String privateKeyStr, String encryptedData) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromString(privateKeyStr);
        byte[] bytes = doCipher(Cipher.DECRYPT_MODE, privateKey, Base64.decodeBase64(encryptedData));
        return new String(bytes);
    }

    /**
     * 使用数据接收方的公钥加密
     *
     * @param publicKeyPath 公钥文件路径
     * @param data          待加密数据
     * @return
     * @throws Exception
     */
    public static String encryptByPublicKeyFile(String publicKeyPath, String data) throws Exception {
        PublicKey publicKey = getPublicKeyFromFile(publicKeyPath);
        byte[] bytes = doCipher(Cipher.ENCRYPT_MODE, publicKey, data.getBytes());
        return Base64.encodeBase64String(bytes);
    }

    /**
     * 数据接收方使用自己的私钥解密
     *
     * @param privateKeyPath 私钥文件路径
     * @param encryptedData  待解密数据
     * @return
     * @throws Exception
     */
    public static String decryptByPrivateKeyFile(String privateKeyPath, String encryptedData) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromFile(privateKeyPath);
        byte[] bytes = doCipher(Cipher.DECRYPT_MODE, privateKey, Base64.decodeBase64(encryptedData));
        return new String(bytes);
    }

    /**
     * 数据发送方使用自己的私钥对数据签名
     *
     * @param privateKeyStr BASE64编码格式的私钥
     * @param data          待签名数据
     * @return 签名数据，一般进行BASE64编码后发送给对方
     * @throws Exception
     */
    public static String signByPrivateKeyStr(String privateKeyStr, String data) throws Exception {
        PrivateKey privateKey = getPrivateKeyFromString(privateKeyStr);
        byte[] bytes = sign(privateKey, data.getBytes());
        return Base64.encodeBase64String(bytes);
    }

    /**
     * 数据接收方使用对方公钥验证签名
     *
     * @param publicKeyStr BASE64编码格式的私钥
     * @param data         待验签数据
     * @param sign         签名数据，进行BASE64解码后验证签名
     * @return
     * @throws Exception
     */
    public static boolean verifyByPublicKeyStr(String publicKeyStr, String data, String sign) throws Exception {
        PublicKey publicKey = getPublicKeyFromString(publicKeyStr);
        return verify(publicKey, data.getBytes(), Base64.decodeBase64(sign));
    }

    private static PublicKey getPublicKeyFromString(String publicKeyStr) throws Exception {
        byte[] encodedKey = Base64.decodeBase64(publicKeyStr);
        return generatePublic(encodedKey);
    }

    private static PublicKey getPublicKeyFromFile(String publicKeyPath) throws Exception {
        byte[] encodedKey = Files.readAllBytes(Paths.get(publicKeyPath));
        return generatePublic(encodedKey);
    }

    private static PublicKey generatePublic(byte[] encodedKey) throws Exception {
        X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        PublicKey publicKey = keyFactory.generatePublic(keySpec);
        return publicKey;
    }

    private static PrivateKey getPrivateKeyFromString(String privateKeyStr) throws Exception {
        byte[] encodedKey = Base64.decodeBase64(privateKeyStr);
        return generatePrivate(encodedKey);
    }

    private static PrivateKey getPrivateKeyFromFile(String privateKeyPath) throws Exception {
        byte[] encodedKey = Files.readAllBytes(Paths.get(privateKeyPath));
        return generatePrivate(encodedKey);
    }

    private static PrivateKey generatePrivate(byte[] encodedKey) throws Exception {
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encodedKey);
        KeyFactory keyFactory = KeyFactory.getInstance(ALGORITHM_RSA);
        PrivateKey privateKey = keyFactory.generatePrivate(keySpec);
        return privateKey;
    }

    private static byte[] doCipher(int mode, Key key, byte[] bytes) throws Exception {
        Cipher cipher = Cipher.getInstance(PADDING);
        cipher.init(mode, key);
        return cipher.doFinal(bytes);
    }

    private static byte[] sign(PrivateKey privateKey, byte[] data) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM_SIGNATURE);
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    private static boolean verify(PublicKey publicKey, byte[] data, byte[] sign) throws Exception {
        Signature signature = Signature.getInstance(ALGORITHM_SIGNATURE);
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(sign);
    }
}

