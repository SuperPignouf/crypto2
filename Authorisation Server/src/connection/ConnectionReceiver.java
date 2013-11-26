package connection;

import java.io.IOException;
import java.net.ServerSocket;

import crypto.RsaKey;

public class ConnectionReceiver {

	private ServerSocket myService;

	/**
	 * Constructor: create the server.
	 * @param rsaKey
	 * @throws IOException
	 */
	public ConnectionReceiver(RsaKey rsaKey) throws IOException{
		initSocketConnection();
		acceptConnections(rsaKey);
	}

	/**
	 * Accepts connection with clients.
	 * @param rsaKey
	 */
	private void acceptConnections(RsaKey rsaKey) {
		while(true){			
			try {
				AuthorisationServer AS = new AuthorisationServer(this.myService.accept(), rsaKey);
				AS.run();
				
				System.out.println("SERVER: Connexion entrante !");
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
