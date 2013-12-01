
package connection;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import crypto.RsaKey;

/**
 * The "main" class of the Client. It starts by connecting to the Authorisation Server to receive a "cryptoperiodic" session key (WS-Client AES key), and then
 * connects to the desired Web Service in a symmetric encryption style using this key.
 */
public class Client {

	private SecretKey WSClientAESKey; // The AS-WS AES session key.
	private int WSID;
	private Socket toWS;
	
	public Client(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		this.WSID = chooseService();
		ClientToAuthorisationServerUsingRSA TAS = new ClientToAuthorisationServerUsingRSA(this.WSID, rsaKey);
		this.WSClientAESKey = TAS.getWSClientAESKey(); // Get the WS-Client AES session key from the AS.
		
		/*if (this.WSID == 1)
			initConnectionWithBlackboard();
		else if (this.WSID == 2)
			initConnectionWithKeychain();
		sendRequestToWS();*/
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
	private void initConnectionWithBlackboard() throws IOException{
		this.toWS = new Socket("localhost", 4224);
	}
	
	/**
	 * Opens a connection to the second Web Service (virtual keychain server, port 4224).
	 * @throws IOException
	 */
	private void initConnectionWithKeychain() throws IOException{
		this.toWS = new Socket("localhost", 4242);
	}
	
	private void sendRequestToWS() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, this.WSClientAESKey);
		String req="";
		do {
			System.out.println("Please enter what you want to send to the Web Service:");
			Scanner sc = new Scanner(System.in);
			req = sc.next();
			SealedObject request = new SealedObject(req, cipher);
			ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
			outO.writeObject(request);
			outO.flush();
		} while(req!="");
		System.out.println("end");
	}
}