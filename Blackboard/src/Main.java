import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import connection.ToAuthorisationServer;
import crypto.RsaKey;

public class Main {
	public static void main(String[] args) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException{
		ToAuthorisationServer TAS = new ToAuthorisationServer(new RsaKey());
	}
}
