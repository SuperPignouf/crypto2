package connection;

import java.io.IOException;
import java.net.ServerSocket;

import crypto.RsaKey;

public class ConnectionReceiver {

	private ServerSocket myService;

	public ConnectionReceiver(RsaKey rsaKey) throws IOException{
		
		initConnection();
		acceptConnections(rsaKey);
	}


	private void acceptConnections(RsaKey rsaKey) {
		while(true){			
			try {
				AuthorisationService AS = new AuthorisationService(this.myService.accept(), rsaKey);
				AS.run();
				
				System.out.println("SERVER: Connexion entrante !");
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}

	}


	private void initConnection() throws IOException {
		this.myService = new ServerSocket(2442);
	}

}
