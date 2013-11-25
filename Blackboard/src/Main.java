import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import connection.ToAuthorisationServer;
import crypto.RsaKey;

public class Main {
	public static void main(String[] args){
		ToAuthorisationServer TAS = new ToAuthorisationServer(new RsaKey());
	}
}
