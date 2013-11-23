package connection;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class AuthorisationService implements Runnable {

	private Socket clientSocket;
	
	public AuthorisationService(Socket clientSocket) {
		this.clientSocket = clientSocket;
	}

	@Override
	public void run() {
		BufferedReader input = null; //Ouverture d'un canal d'entree
		try {
			input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		PrintWriter output = null; //Ouverture d'un canal de sortie
		try {
			output = new PrintWriter(this.clientSocket.getOutputStream(), true);
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
		// Ici on peut envoyer des messages au client.
		output.println("Coucou, client !");
		
		try {
	        output.close();
	        input.close();
	        this.clientSocket.close();
	        
	     } 
	     catch (IOException e) {
	        System.out.println(e);
	     }
		
	}

}
