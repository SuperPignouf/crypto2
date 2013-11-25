package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;


public class RsaKey {

	private KeyPair keyPair;


	public RsaKey(){
		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		keyPairGenerator.initialize(1024);
		this.keyPair = keyPairGenerator.genKeyPair();
	}

	public KeyPair getKeyPair(){
		return this.keyPair;
	}

}
