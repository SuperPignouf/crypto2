package connection;

import java.io.IOException;
import java.net.ServerSocket;

import crypto.RsaKey;

public class ConnectionReceiver {

	private ServerSocket myService;

	public ConnectionReceiver(RsaKey rsaKey){


		this.myService = null; //Socket du serveur

		try {
			this.myService = new ServerSocket(2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		System.out.println("SERVER: Serveur d'authentification en ligne...");
		while(true){			
			try {
				AuthorisationService AS = new AuthorisationService(myService.accept());
				AS.run();
				
				System.out.println("SERVER: Connexion acceptee !");
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}

}
