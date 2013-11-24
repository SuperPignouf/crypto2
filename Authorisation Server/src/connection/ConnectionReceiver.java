package connection;

import java.io.IOException;
import java.net.ServerSocket;

import crypto.RsaKey;

public class ConnectionReceiver {

	private ServerSocket myService;

	public ConnectionReceiver(RsaKey rsaKey){
		
		initConnection();
		while(true) acceptConnection(rsaKey);
	}


	private void acceptConnection(RsaKey rsaKey) {
		while(true){			
			try {
				AuthorisationService AS = new AuthorisationService(myService.accept(), rsaKey);
				AS.run();
				
				//System.out.println("SERVER: Connexion acceptee !");
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
		
	}


	private void initConnection() {
		this.myService = null; //Socket du serveur

		try {
			this.myService = new ServerSocket(2442);
			//System.out.println("SERVER: Serveur d'authentification en ligne...");
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
	}

}
