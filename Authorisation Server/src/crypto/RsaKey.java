package crypto;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;


public class RsaKey {

	private KeyPair keyPair;


	public RsaKey() throws NoSuchAlgorithmException{
		KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
		keyPairGenerator.initialize(1024);
		this.keyPair = keyPairGenerator.genKeyPair();
	}

	public KeyPair getKeyPair(){
		return this.keyPair;
	}

}
