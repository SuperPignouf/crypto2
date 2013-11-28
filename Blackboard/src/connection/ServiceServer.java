package connection;

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import crypto.RsaKey;

public class ServiceServer {
	
	private SecretKey ASAESKey;

	public ServiceServer(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		ToAuthorisationServer TAS = new ToAuthorisationServer(rsaKey);
		this.ASAESKey = TAS.getASAESKey();
	}

	
}
