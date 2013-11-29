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
 * Class to create the Authorization server: it initializes the socket. 
 */
public class AuthorizationServer {

	private SecretKey bbSessionKey;
	private SecretKey kcSessionKey;
	private ServerSocket myService;

	/**
	 * Constructor: create the Authorization Server.
	 * @param rsaKey the pair of keys (public and private) RSA.
	 * @throws IOException
	 */
	public AuthorizationServer(RsaKey rsaKey) throws IOException{
		initSocketConnection();
		acceptConnections(rsaKey);
	}

	/**
	 * Server: accepts connection with clients. 
	 * Runs the thread that identifies the client (with RSA).
	 * If the client has been identified, it distributes securely a symmetric key (AES).
	 * @param rsaKey
	 */
	private void acceptConnections(RsaKey rsaKey) {
		while(true){			
			try {
				//AuthorizationService AS = new AuthorizationService(this.myService.accept(), rsaKey, this);
				//AS.run();
				new AuthorizationService(this.myService.accept(), rsaKey, this).run();
			}
			
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}


	/**
	 * Initializes the socket.
	 * Port = 2442.
	 * @throws IOException
	 */
	private void initSocketConnection() throws IOException {
		this.myService = new ServerSocket(2442);
	}

	public void setBBSessionKey(SecretKey aesServiceKey) {
		this.bbSessionKey = aesServiceKey;	
	}
	
	public void setKCSessionKey(SecretKey aesServiceKey) {
		this.kcSessionKey = aesServiceKey;	
	}

	// On va se connecter au Web service designe par wsid et 
	//lui envoyer la cle aes et la clientID pour que client et WS puissent parler
	public void transmitAESToWS(SecretKey aesKey, int wsid, int clientID) throws UnknownHostException, IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException { 
		Socket toWS;
		if (wsid == 1){ // Cas du blackboard
			toWS = new Socket("localhost", 4224);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, this.bbSessionKey);
			SealedObject encryptedaesKey = new SealedObject(aesKey.getEncoded(), cipher);
			ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
			int myID = 0;
			outO.writeObject(myID);
			outO.flush();
			outO.writeObject(encryptedaesKey);
			outO.flush();
			
			outO.close();
			toWS.close();
		}
		else if (wsid == 2){ // Cas du keychain
			toWS = new Socket("localhost", 4242);
			Cipher cipher = Cipher.getInstance("AES");
			cipher.init(Cipher.ENCRYPT_MODE, this.kcSessionKey);
			SealedObject encryptedaesKey = new SealedObject(aesKey.getEncoded(), cipher);
			ObjectOutputStream outO = new ObjectOutputStream(toWS.getOutputStream());
			int myID = 0;
			outO.writeObject(myID);
			outO.flush();
			outO.writeObject(encryptedaesKey);
			outO.flush();
			
			outO.close();
			toWS.close();
		}
		
		
	}

}
