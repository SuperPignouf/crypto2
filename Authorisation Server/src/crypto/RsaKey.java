package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

/**
 * Class to create a pair of keys (public and private) RSA.
 */
public class RsaKey {

	private KeyPair keyPair;

	/**
	 * Constructor: create a pair of keys (public and private) RSA.
	 */
	public RsaKey(){
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
