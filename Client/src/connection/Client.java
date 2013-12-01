
package connection;

import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
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
	private int ID, WSID;
	private Socket toWS;
	
	public Client(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		//this.ID = new Scanner(new File("src/ID.txt")).nextInt(); //TODO
		this.ID = new Scanner(new File("ID.txt")).nextInt();
		this.WSID = chooseService();
		ClientToAuthorisationServerUsingRSA TAS = new ClientToAuthorisationServerUsingRSA(this.ID, this.WSID, rsaKey);
		this.WSClientAESKey = TAS.getWSClientAESKey(); // Get the WS-Client AES session key from the AS.
		
		if (this.WSID == 1) {
			initConnectionWithBlackboard();
			sendRequestToBlackboard();
		}
		else if (this.WSID == 2) {
			initConnectionWithKeychain();
			sendRequestToKeychain();
		}
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
		this.toWS = new Socket("localhost", 4225);
	}
	
	private void sendRequestToBlackboard() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, this.WSClientAESKey);
		
		//identification to the Web Service
		SealedObject request = new SealedObject(this.ID, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toWS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		
		//msg received from the Web Service
		ObjectInputStream in = new ObjectInputStream(this.toWS.getInputStream());
		SealedObject sealedMsg = (SealedObject) in.readObject();
		cipher.init(Cipher.DECRYPT_MODE, this.WSClientAESKey);
		String msg = (String) sealedMsg.getObject(cipher);
		System.out.println(msg);
		
		//Messages that the user wants to send to the Web Service
		cipher.init(Cipher.ENCRYPT_MODE, this.WSClientAESKey);
		String req="";
		do {
			System.out.println("Please enter what you want to send to the Web Service:");
			Scanner sc = new Scanner(System.in);
			req = sc.nextLine();
			request = new SealedObject(req, cipher);
			outO = new ObjectOutputStream(toWS.getOutputStream());
			outO.writeObject(request);
			outO.flush();
		} while(!req.equals(" "));
		System.out.println("END");
	}
	
	private void sendRequestToKeychain() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, ClassNotFoundException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, this.WSClientAESKey);
		
		//identification to the Web Service
		SealedObject request = new SealedObject(this.ID, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toWS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		
		//msg received from the Web Service
		ObjectInputStream in = new ObjectInputStream(this.toWS.getInputStream());
		SealedObject sealedMsg = (SealedObject) in.readObject();
		cipher.init(Cipher.DECRYPT_MODE, this.WSClientAESKey);
		String msg = (String) sealedMsg.getObject(cipher);
		System.out.println(msg);
		
		//Messages that the user wants to send to the Web Service
		cipher.init(Cipher.ENCRYPT_MODE, this.WSClientAESKey);
		String req="";
		do {
			System.out.println("Please enter what you want to send to the Web Service:");
			Scanner sc = new Scanner(System.in);
			req = sc.next();
			request = new SealedObject(req, cipher);
			outO = new ObjectOutputStream(toWS.getOutputStream());
			outO.writeObject(request);
			outO.flush();
		} while(req!="");
		System.out.println("end");
	}
	
}