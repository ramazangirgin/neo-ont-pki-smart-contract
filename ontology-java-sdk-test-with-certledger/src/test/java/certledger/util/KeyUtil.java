package certledger.util;

import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.encoders.Hex;
import org.bouncycastle.util.io.pem.PemReader;

import java.io.FileReader;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

public class KeyUtil {

    public static KeyPair generateNISTp348KeyPair() throws Exception {
        Security.addProvider(new BouncyCastleProvider());
        ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp384r1");
        KeyPairGenerator g = KeyPairGenerator.getInstance("ECDSA", "BC");
        g.initialize(ecSpec, new SecureRandom());
        return g.generateKeyPair();
    }

    public static void generateNISTp348KeyPairAndSaveToFile(String filePath) throws Exception {
        KeyPair keyPair = KeyUtil.generateNISTp348KeyPair();
        byte[] encodedPublicKey = keyPair.getPublic().getEncoded();
        SubjectPublicKeyInfo subjectPublicKeyInfo = SubjectPublicKeyInfo.getInstance(
                ASN1Sequence.getInstance(encodedPublicKey));
        byte[] subjectPublicKeyInfoEncoded = subjectPublicKeyInfo.getEncoded();
        System.out.println("************** SUBJECT PUBLIC KEY INFO ENCODED HEX ******************");
        System.out.println(Hex.toHexString(subjectPublicKeyInfoEncoded));
        System.out.println("*****************************************************************");

        PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(keyPair.getPrivate().getEncoded());
        byte[] pkcs8KeyEncoded = pkcs8EncodedKeySpec.getEncoded();

        System.out.println("************** PKCS8 PRIVATE KEY ENCODED HEX ******************");
        System.out.println(Hex.toHexString(pkcs8KeyEncoded));
        System.out.println("*****************************************************************");

        Files.write(Paths.get(filePath), pkcs8KeyEncoded);
    }

    public static PrivateKey loadPrivateKey(String filePath) {
        try {
            byte[] signPrivateKeyBytes = Files.readAllBytes(Paths.get(filePath));
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(signPrivateKeyBytes);
            return KeyFactory.getInstance("EC", "BC").generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception exc) {
            throw new RuntimeException("Private Key Load Error", exc);
        }
    }

    public static PrivateKey loadRSAPrivateKeyFromPemFile(String filePath) {
        try {
            PemReader pemReader = new PemReader(new FileReader(filePath));
            byte[] privateKeyBytes = pemReader.readPemObject().getContent();
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return KeyFactory.getInstance("RSA", "BC").generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception exc) {
            throw new RuntimeException("Private Key Load Error", exc);
        }
    }

    public static PrivateKey loadECPrivateKeyFromPemFile(String filePath) {
        try {
            PemReader pemReader = new PemReader(new FileReader(filePath));
            byte[] privateKeyBytes = pemReader.readPemObject().getContent();
            PKCS8EncodedKeySpec pkcs8EncodedKeySpec = new PKCS8EncodedKeySpec(privateKeyBytes);
            return KeyFactory.getInstance("EC", "BC").generatePrivate(pkcs8EncodedKeySpec);
        } catch (Exception exc) {
            throw new RuntimeException("Private Key Load Error", exc);
        }
    }
}
