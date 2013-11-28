package connection;

import java.io.IOException;
import java.net.ServerSocket;

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
				AuthorizationService AS = new AuthorizationService(this.myService.accept(), rsaKey, this);
				AS.run();
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
	public void transmitAESToWS(SecretKey aesKey, int wsid, int clientID) { 
		// TODO Auto-generated method stub
		
	}

}
