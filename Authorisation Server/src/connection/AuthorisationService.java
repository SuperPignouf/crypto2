package connection;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class AuthorisationService implements Runnable {

	private Socket clientSocket;
	
	public AuthorisationService(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}

	@Override
	public void run() {
		DataInputStream input = null; //Ouverture d'un canal d'entree
		try {
			input = new DataInputStream(clientSocket.getInputStream());
		}
		catch (IOException e) {
			System.out.println(e);
		}

		DataOutputStream output = null; //Ouverture d'un canal de sortie
		try {
			output = new DataOutputStream(clientSocket.getOutputStream());
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
		try {
	        output.close();
	        input.close();
	        clientSocket.close();
	        
	     } 
	     catch (IOException e) {
	        System.out.println(e);
	     }
		
	}

}
