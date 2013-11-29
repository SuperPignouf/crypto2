import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import connection.AuthorizationServer;
import crypto.RsaKey;

/**
 * Main class: Create the authorization server.
 */
public class Main {
	
	/**
	 * Main: create the Authorization Server.
	 * @param args arguments for the main.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void main(String[] args){
		try {
			try {
				@SuppressWarnings("unused")
				AuthorizationServer AS = new AuthorizationServer(new RsaKey());
			} catch (NoSuchAlgorithmException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			} catch (IOException e) {
				// TODO Auto-generated catch block
				e.printStackTrace();
			}
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}
	
}
