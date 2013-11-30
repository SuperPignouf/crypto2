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
 * The "main" class of the AS. It creates the Authorisation Server, connects with clients using RSA encryption and finally transmits 
 */
public class AuthorisationServer {

	private SecretKey ASBlackboardAESKey, ASKeychainAESKey;
	private ServerSocket myService;

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
				new RSASecuredService(this.myService.accept(), rsaKey, this).run();
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
	 * Transmits the WS-Client AES "cryptoperiodic" session key to the appropriate WS.
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
		Socket toWS;
		if (WSID == 1){ // If Blackboard.
			toWS = new Socket("localhost", 4224);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, this.ASBlackboardAESKey);
			SealedObject encryptedBBClientAESKey = new SealedObject(WSClientAESKey.getEncoded(), cipher);
			ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
			int myID = 0;
			outO.writeObject(myID);
			outO.flush();
			outO.writeObject(encryptedBBClientAESKey);
			outO.flush();
			
			outO.close();
			toWS.close();
		}
		else if (WSID == 2){ // If Keychain.
			toWS = new Socket("localhost", 4242);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, this.ASKeychainAESKey);
			SealedObject encryptedKCClientKey = new SealedObject(WSClientAESKey.getEncoded(), cipher);
			ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
			int myID = 0;
			outO.writeObject(myID);
			outO.flush();
			outO.writeObject(encryptedKCClientKey);
			outO.flush();
			
			outO.close();
			toWS.close();
		}
		
		
	}

}
