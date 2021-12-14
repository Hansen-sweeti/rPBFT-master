package cc.weno.ca.s;

import java.security.Security;

public class main {
    public static void main(String[] args ){
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        Signservice signservice=new Signservice();
        String sign =signservice.signAndEncode("C:\\Users\\ASUS\\Desktop\\CA\\rootca.pem");
        System.out.println(sign);
        //String source=signservice.signature("C:\\Users\\ASUS\\Desktop\\CA\\rootca.der");
        signservice.init();
        if(signservice.verify(sign)){
            System.out.println("ok");
        }
    }
}
