package mb.test;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.util.Properties;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.CipherOutputStream;

/**
 * Hello world!
 *
 */
public class App {

    public static void main(String[] args) {
        MessagePropertiesTest();
    }

    public static void MessagePropertiesTest() {

        // fajny art o kluczach https://www.pixelstech.net/article/1439554008-Java-Cipher-encryption-decryption-example
        // fajny art o jksach https://gist.github.com/nielsutrecht/855f3bef0cf559d8d23e94e2aecd4ede
        Properties props = new Properties();
        Properties props2 = new Properties();

        props.put("Name", "Ala");
        props.put("Pet", "kot");

        File f = new File("props.xml");
        FileOutputStream fos = null;
        File f2 = new File("props.txt");
        FileOutputStream fos2 = null;
        File f3 = new File("secret.txt");
        FileOutputStream fos3 = null;
        FileInputStream fis3 = null;
        Cipher cipher = null;
        // KeyGenerator keyGenerator = null; -- do generowania certa. Potem uzywałem certa z jksa
        CipherOutputStream cos = null;
        CipherInputStream cis = null;

        PublicKey publicKey = null;
        PrivateKey privateKey = null;
        KeyStore.PasswordProtection keyPassword = new KeyStore.PasswordProtection("password".toCharArray());
        KeyPair keyPair = null;

        KeyStore ks = getKeystore("mbkeystore.jks", "password");
        try {
            //key = ks.getKey("mbkey", "password".toCharArray());

            KeyStore.PrivateKeyEntry privateKeyEntry = (KeyStore.PrivateKeyEntry) ks.getEntry("mbkey", keyPassword);

            Certificate cert = ks.getCertificate("mbkey");
            publicKey = cert.getPublicKey();
            privateKey = privateKeyEntry.getPrivateKey();

            keyPair = new KeyPair(publicKey, privateKey);

        } catch (KeyStoreException | NoSuchAlgorithmException | UnrecoverableEntryException e) {
            e.printStackTrace();
        }

        props.list(System.out);

        try {

            fos = new FileOutputStream(f);
            fos2 = new FileOutputStream(f2);
            fos3 = new FileOutputStream(f3);
            fis3 = new FileInputStream(f3);

            // zaremowałem od kiedy zaczałem używać certa z JKSa
//			keyGenerator = KeyGenerator.getInstance("AES");
//			keyGenerator.init(128);
//			//secretKey  = keyGenerator.generateKey();
//			key = keyGenerator.generateKey();
            //cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
            cipher = Cipher.getInstance("RSA");
            cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
            cos = new CipherOutputStream(fos3, cipher);

            props.storeToXML(fos, "Propertisy");
            props.store(fos2, "Propertisy");
            props.store(cos, "Propertisy");
            cos.close();

            //cipher.init(Cipher.DECRYPT_MODE, key, cipher.getParameters() );
            cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
            cis = new CipherInputStream(fis3, cipher);

            props2.load(cis);
            props2.list(System.out);

        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            try {
                if (fos != null) {
                    fos.close();
                }
                if (fos2 != null) {
                    fos2.close();
                }
                if (fos3 != null) {
                    fos3.close();
                }
                if (fis3 != null) {
                    fis3.close();
                }
            } catch (IOException e) {
                // TODO Auto-generated catch block
                e.printStackTrace();
            }
        }
    }

    public static KeyStore getKeystore(String fileName, String password) {
        KeyStore ks = null;
        try {
            ks = KeyStore.getInstance("JKS");
            FileInputStream fis = new FileInputStream(new File(fileName));
            ks.load(fis, password.toCharArray());
        } catch (Exception e) {
            e.printStackTrace();
        }
        return ks;
    }

}
