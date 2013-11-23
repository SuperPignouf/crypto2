package connection;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;

public class ConnectionReceiver {

	private ServerSocket myService;

	public ConnectionReceiver(){


		this.myService = null; //Socket du serveur

		try {
			this.myService = new ServerSocket(2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		while(true){

			Socket clientSocket = null; //Socket ouvert pour chaque client
			try {
				clientSocket = myService.accept();
			}
			catch (IOException e) {
				System.out.println(e);
			}
			
			AuthorisationService AS = new AuthorisationService(clientSocket);
			AS.run();		    
		}

	}
	
	
}
