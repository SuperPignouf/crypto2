import java.io.IOException;
import java.security.NoSuchAlgorithmException;

import connection.ConnectionReceiver;
import crypto.RsaKey;

/**
 * Main class: Create a connectionReceiver.
 */
public class Main {
	
	/**
	 * Main: create a connectionReceiver.
	 * @param args arguments for the main.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void main(String[] args) throws NoSuchAlgorithmException, IOException{
		ConnectionReceiver CR = new ConnectionReceiver(new RsaKey());
	}
	
}
