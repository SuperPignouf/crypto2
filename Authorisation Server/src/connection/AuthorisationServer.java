package connection;

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.net.ServerSocket;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import crypto.RsaKey;

/**
 * The "main" class of the AS. It creates the Authorization Server, connects with clients using RSA encryption and finally transmits 
 */
public class AuthorisationServer {

	private int ID = 0;
	private int cryptoperiod = 7200;
	private SecretKey ASBlackboardAESKey, ASKeychainAESKey;
	private ServerSocket myService;
	private Socket clientSocket = null;
	private Thread t;

	/**
	 * Constructor: creates the Authorization Server.
	 * @param rsaKey - The pair of keys (public and private) RSA.
	 * @throws IOException
	 */
	public AuthorisationServer(RsaKey rsaKey) throws IOException{
		initSocketConnection();
		acceptConnections(rsaKey);
	}

	/**
	 * Accepts connections with Clients. 
	 * Runs the thread that identifies the client (with RSA).
	 * If the Client has been identified, it distributes securely a symmetric key (AES).
	 * @param rsaKey
	 */
	private void acceptConnections(RsaKey rsaKey) {
		while(true){			
			try {
				this.clientSocket = this.myService.accept();
				System.out.println("AS: Someone wants to connect.");
				t = new Thread(new RSASecuredService(this, this.clientSocket, rsaKey, this.ID, this.cryptoperiod));
				;
			} catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}


	/**
	 * Initializes the socket (port 2442).
	 * @throws IOException
	 */
	private void initSocketConnection() throws IOException {
		this.myService = new ServerSocket(2442);
	}
	
	/**
	 * Sets the AS-Blackboard AES session key.
	 * @param AESKey
	 */
	public void setASBlackboardAESKey(SecretKey AESKey) {
		this.ASBlackboardAESKey = AESKey;
	}
	
	/**
	 * Sets the AS-Keychain AES session key.
	 * @param AESKey
	 */
	public void setASKeychainAESKey(SecretKey AESKey) {
		this.ASKeychainAESKey = AESKey;
	}

	/**
	 * Transmits the WS-Client AES "cryptoperiodic" session key to the appropriate Web Service.
	 * @param WSClientAESKey
	 * @param WSID
	 * @param clientID
	 * @throws UnknownHostException
	 * @throws IOException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 */
	public void transmitWSClientAESKeyToWS(SecretKey WSClientAESKey, int WSID, int clientID) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException { 
		Socket toWS = null;
		if (WSID == 1) // If Blackboard.
			toWS = new Socket("localhost", 4224);
		else if (WSID == 2) // If Keychain.
			toWS = new Socket("localhost", 4242);
		
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASBlackboardAESKey);
		SealedObject encryptedClientID = new SealedObject(clientID, cipher);
		SealedObject encryptedBlackboardClientAESKey = new SealedObject(WSClientAESKey.getEncoded(), cipher);
		SealedObject encryptedCryptoperiod = new SealedObject(this.cryptoperiod, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		outO.writeObject(encryptedClientID);
		outO.flush();
		outO.writeObject(encryptedBlackboardClientAESKey);
		outO.flush();
		outO.writeObject(encryptedCryptoperiod);
		outO.flush();

		outO.close();
		toWS.close();
	}

}
