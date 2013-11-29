package crypto;

import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;

/**
 * Class to create a pair of keys (public and private) RSA.
 */
public class RsaKey {

	private KeyPair keyPair;

	/**
	 * Constructor: create a pair of keys (public and private) RSA.
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 */
	public RsaKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException{
		
//		File file = new File("src\\chicken.der");
//		FileInputStream fis = new FileInputStream(file);
//		DataInputStream dis = new DataInputStream(fis);
//		byte[] keyBytes = new byte[(int)file.length()];
//	    dis.readFully(keyBytes);
//	    dis.close();
//		
//	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
//	    KeyFactory kf = KeyFactory.getInstance("RSA");
//	    PrivateKey pk = kf.generatePrivate(spec);
//
//		System.out.println(spec);
//		fis.close();
		
		KeyPairGenerator keyPairGenerator = null;
        try {
                keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //RSA
        } catch (NoSuchAlgorithmException e) {
                e.printStackTrace();
        }
        keyPairGenerator.initialize(1024); //1024 bits
        this.keyPair = keyPairGenerator.genKeyPair();
	}

	/**
	 * Returns the key public and private.
	 * @return keyPair the pair of keys
	 */
	public KeyPair getKeyPair(){
		return this.keyPair;
	}

}
