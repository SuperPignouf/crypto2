package connection;

import java.io.IOException;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import crypto.RsaKey;

/**
 * The "main" class of the Client. It starts by connecting to the Authorisation Server to receive a "cryptoperiodic" session key (WS-Client AES key), and then
 * connects to the desired Web Service in a symmetric encryption style using this key.
 */
public class Client {

	private SecretKey WSClientAESKey; // The AS-WS AES session key.
	private int WSID;
	private Socket toBB, toKC;
	
	public Client(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		this.WSID = chooseService();
		ClientToASCommunicationUsingRSA TAS = new ClientToASCommunicationUsingRSA(this.WSID, rsaKey);
		this.WSClientAESKey = TAS.getWSClientAESKey(); // Get the WS-Client AES session key from the AS.
		
	}
	
	/**
	 * Allows the user to select a Web Service.
	 */
	private int chooseService() {
		String response;
		do {
			System.out.println("Hello, which service would you access to ? (blackboard: 1 , keychain: 2 )");
			Scanner sc = new Scanner(System.in);
			response = sc.next();
		}
		while (!"1".equals(response) && !"2".equals(response));
		
		return Integer.parseInt(response);
	}
	
	/**
	 * Opens a connection to the first Web Service (virtual blackboard, port 4224).
	 * @throws IOException
	 */
	private void initConnectionWithWS1() throws IOException{
		this.toBB = new Socket("localhost", 4224);
	}
	
	/**
	 * Opens a connection to the second Web Service (virtual keychain server, port 4224).
	 * @throws IOException
	 */
	private void initConnectionWithWS2() throws IOException{
		this.toKC = new Socket("localhost", 4242);
	}
}
