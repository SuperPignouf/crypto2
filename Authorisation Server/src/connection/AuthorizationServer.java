package connection;

import java.io.IOException;
import java.net.ServerSocket;

import crypto.RsaKey;

/**
 * Class to create the Authorization server: it initializes the socket. 
 */
public class AuthorizationServer {

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
				AuthorizationService AS = new AuthorizationService(this.myService.accept(), rsaKey);
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

}
