package cc.weno.ca;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

public class rootCA {
    private static final String SUBJECT = "C=CN,S=BJ,L=BJ,O=PKU,OU=PKU_SM,CN=BC_CA";
    //String issuer = "C=CN,ST=BJ,L=BJ,O=SICCA,OU=SC,CN=SICCA";
			/*
			C=CN;S=BeiJing;L=BeiJing;O=PKU;OU=ICST;CN=wolfenstein
		    这里C是国家和地区代码,S和L都是地区代码,S相当于省或者州这样的级别,L相当于城市级别,O是组织机构名称,OU是次级组织机构名称,CN是主体的 通用名(common name).
		    在这里,C,S,L等等属性的类型都是相对固定的,例如C一般就是用来表示国家和地区代码,在DN结构中还可以添加一些其它类型的信息,一般 也都是以"xxx=xxx"这样来表示的.
			*/

    public static void main(String[] args) throws NoSuchAlgorithmException, NoSuchProviderException, IOException, CertificateException {

        //Security.addProvider(new BouncyCastleProvider());

//		creatRootCA();

        //readCA();

//		readKeyStore();
        SecretKeySpec sc = new SecretKeySpec(null, "");
    }

    private static void readKeyStore() {
        String pass = "1qaz2wsx";
        String filepath = "E:/test.pfx";
        System.out.println("begin ca.");
        try {

            FileInputStream file_inputstream = new FileInputStream(filepath);
            KeyStore store = KeyStore.getInstance("PKCS12", "BC");
            store.load(file_inputstream, pass.toCharArray());

            PrivateKey key = (PrivateKey) store.getKey("ljttest", pass.toCharArray());
            System.out.println("PrivateKey:" + key);
            java.security.cert.Certificate ca = store.getCertificate("ljttest");

            if (store.getCertificate("ljttest") == null) {
                System.out.println("Failed to find UTF cert.");
            }
            System.out.println("ca." + ca);

        } catch (NoSuchAlgorithmException | CertificateException | IOException | KeyStoreException | NoSuchProviderException | UnrecoverableKeyException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
    }

    private static void readCA() throws IOException, CertificateException {
        String filepath = "E:/BouncyCastle_JCE/ljtTest1.cer";
        CertificateFactory certificate_factory = CertificateFactory.getInstance("X.509");
        FileInputStream file_inputstream = new FileInputStream(filepath);
        X509Certificate x509certificate = (X509Certificate) certificate_factory.generateCertificate(file_inputstream);

        String Field = x509certificate.getType();
        Date nobefore = x509certificate.getNotAfter();
        System.out.println("nobefore:" + nobefore);
    }

    public static void creatRootCA() throws NoSuchAlgorithmException, NoSuchProviderException, CertificateEncodingException {

        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        KeyPair kp = kpg.generateKeyPair();
        PublicKey pubk = kp.getPublic();
        PrivateKey prik = kp.getPrivate();

        X509Certificate x509ca = generateV3SelfSignedCertificate(pubk, prik, SUBJECT);
        byte[] caByte = x509ca.getEncoded();

		/*
		//root ca save to local
		String filePath = "C:/pku/blockchian/bcRoot.cer";
		try {
			File f = new File(filePath);
	        if (!f.exists()) {
	            f.createNewFile();
	        }

	        FileOutputStream fos = new FileOutputStream(f);
			fos.write(caByte);
	        fos.flush();
	        fos.close();
		} catch (IOException e) {
			e.printStackTrace();
		}
		*/
        //save to db

        String pfxPath = "C:/pku/rootCA.pfx";
        KeyStore keyStore;
        try {

            keyStore = KeyStore.getInstance("PKCS12", "BC");
            keyStore.load(null, null);

            keyStore.setKeyEntry("ljttest", kp.getPrivate(), "1qaz2wsx".toCharArray(), new X509Certificate[]{x509ca});

            FileOutputStream fos = new FileOutputStream(new File(pfxPath));
            keyStore.store(fos, "1qaz2wsx".toCharArray());
            fos.flush();
            fos.close();

        } catch (KeyStoreException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }


    }


    //Generate version 3 self signed X509Certificate
    private static X509Certificate generateV3SelfSignedCertificate(PublicKey pubk, PrivateKey prik, String subject) {
        try {
            X500Name subjectDN = new X500Name(subject);
            BigInteger serialNumber = BigInteger.valueOf(System.currentTimeMillis());

            Calendar c = Calendar.getInstance();
            Date startDate = c.getTime();
            c.add(Calendar.YEAR, 1);
            Date endDate = c.getTime();

            SubjectPublicKeyInfo subPubKeyInfo = SubjectPublicKeyInfo.getInstance(pubk.getEncoded());

            X509v3CertificateBuilder builder = new X509v3CertificateBuilder(subjectDN, serialNumber, startDate,
                    endDate, subjectDN, subPubKeyInfo);
            X509CertificateHolder holder = builder.build(createSigner(prik));

            return new JcaX509CertificateConverter().getCertificate(holder);
        } catch (Exception e) {
            throw new RuntimeException("Error creating X509v3Certificate.", e);
        }
    }

    private static ContentSigner createSigner(PrivateKey privKey) throws OperatorCreationException {

        return new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(privKey);
    }
}
