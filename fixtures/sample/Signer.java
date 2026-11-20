import java.security.*;
import javax.crypto.Cipher;

class Signer {
  void run() throws Exception {
    KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
    Signature s = Signature.getInstance("SHA256withECDSA");
    Cipher c = Cipher.getInstance("DESede/CBC/PKCS5Padding");
  }
}
