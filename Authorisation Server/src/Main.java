import java.io.IOException;
import java.security.NoSuchAlgorithmException;

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
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException{
		AuthorizationServer CR = new AuthorizationServer(new RsaKey());
	}
	
}
