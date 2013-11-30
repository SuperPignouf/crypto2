package crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
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

/*		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //RSA
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyPairGenerator.initialize(1024); //1024 bits
		this.keyPair = keyPairGenerator.genKeyPair();*/

		// Loading private key file
		
        String keyFile = "src/cakey.p8c";
        InputStream inStream = new FileInputStream(keyFile);
        byte[] encKey = new byte[inStream.available()];
        inStream.read(encKey);
        inStream.close();
        
        // Read the private key from file
        
        System.out.println("RSA PrivateKeyInfo: " + encKey.length + " bytes\n");
        PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        System.out.println("KeyFactory Object Info:");
        System.out.println("Algorithm = "+ keyFactory.getAlgorithm());
        System.out.println("Provider = "+ keyFactory.getProvider());
        PrivateKey priv = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
        System.out.println("Loaded " + priv.getAlgorithm() + " " + priv.getFormat() + " private key.");
	}

	/**
	 * Returns the key public and private.
	 * @return keyPair the pair of keys
	 */
	public KeyPair getKeyPair(){
		return this.keyPair;
	}

}
