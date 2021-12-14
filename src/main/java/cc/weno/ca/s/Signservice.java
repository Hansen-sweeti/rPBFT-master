package cc.weno.ca.s;

//import cc.weno.ca.SignService;
import jdk.nashorn.internal.runtime.regexp.joni.Config;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemReader;
import org.slf4j.LoggerFactory;

import javax.annotation.PostConstruct;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Objects;
import java.util.Optional;
import java.util.logging.Logger;

import static java.util.Base64.getDecoder;
import static java.util.Base64.getEncoder;
import static org.apache.commons.codec.CharEncoding.ISO_8859_1;

public  class Signservice {
    //private static final String ISO_8859_1 = ;
    //private static Logger LOG = (Logger) LoggerFactory.getLogger(SignService.class);


    private Config config;
    private String filename = "C:\\Users\\ASUS\\Desktop\\CA\\rootca.key";
    public Signature signature;

    @PostConstruct
    public void inIt() {
        try {
            //PKCS8EncodedKeySpec priKeySpec = new PKCS8EncodedKeySpec(
             //      getDecoder().decode(config.getPrivateKey().getBytes(ISO_8859_1)));
            byte[] keyBytes = new byte[0];
            try {
                keyBytes = Files.readAllBytes(Paths.get(filename));
            } catch (IOException e) {
                e.printStackTrace();
            }
            PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);

            KeyFactory factory = null;
            try {
                factory = KeyFactory.getInstance("RSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            PrivateKey privateKey = factory.generatePrivate(spec);

            try {
                signature = Signature.getInstance("SHA1WithRSA");
            } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
            }
            try {
                signature.initSign(privateKey);
            } catch (InvalidKeyException e) {
                e.printStackTrace();
            }

        } catch (
                InvalidKeySpecException ex)

        {
            //LOG.warning("RSA init error: {}.", ex);
        }
    }

    String signAndEncode(String source) {
        if (Objects.isNull(filename)) {
            return null;
        } else {
            return sign(source)
                    .map(this::encode)
                    .orElse("");
        }
    }

    private String encode(byte[] source) {
        return getEncoder()
                .encodeToString(source);
    }

    private synchronized Optional<byte[]> sign(String source) {
        try {
            signature.update(source.getBytes(StandardCharsets.ISO_8859_1));
            return Optional.of(signature.sign());
        } catch (SignatureException e) {
            //LOG.log("SHA1WithRSA {} error: {}.", source, e);
            return Optional.empty();
        }
    }
    //@Before
    public void init() {
        try {
            byte[] key = Files.readAllBytes(Paths.get("C:\\Users\\ASUS\\Desktop\\CA\\", "rootca.pem"));

            Security.addProvider(new BouncyCastleProvider());

            final PemObject pemObject;

            try (PemReader pemReader = new PemReader(new InputStreamReader(
                    new ByteArrayInputStream(key)))) {
                pemObject = pemReader.readPemObject();
            }

            X509EncodedKeySpec pubKeySpec = new X509EncodedKeySpec(pemObject.getContent());

            KeyFactory factory = KeyFactory.getInstance("RSA");
            PublicKey publicKey = factory.generatePublic(pubKeySpec);

            signature = Signature.getInstance("SHA1WithRSA");
            signature.initVerify(publicKey);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public boolean verify( String sign) {
        byte[] data = getDecoder().decode(sign);
        try {
            signature.update(filename.getBytes());
            return signature.verify(data);
        } catch (SignatureException e) {
            e.printStackTrace();
            return false;
        }
    }

}