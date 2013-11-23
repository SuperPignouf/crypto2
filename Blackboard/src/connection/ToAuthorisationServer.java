package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;

public class ToAuthorisationServer {

	public 	ToAuthorisationServer(){

		Socket client = null;
		try {
			client = new Socket("localhost", 2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		BufferedReader input = null;
		try {
			input = new BufferedReader(new InputStreamReader(client.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		PrintWriter output = null; //Ouverture d'un canal de sortie
		try {
			output = new PrintWriter(client.getOutputStream(), true);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		// Ici on peut communiquer avec le serveur.
		System.out.println("CLIENT: Attente de reception de texte.");
		try{
			String line = input.readLine();
			System.out.println("CLIENT: Text received: " + line);
		} catch (IOException e){
			System.out.println("Read failed");
			System.exit(1);
		}

		try {
			output.close();
			input.close();
			client.close();
		} 
		catch (IOException e) {
			System.out.println(e);
		}

	}

}
