package connection;

import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.Socket;

public class ToAuthorisationServer {

	public 	ToAuthorisationServer(){

		Socket client = null;
		try {
			client = new Socket("authorisation", 2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		DataInputStream input = null;
		try {
			input = new DataInputStream(client.getInputStream());
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
		DataOutputStream output = null; //Ouverture d'un canal de sortie
		try {
			output = new DataOutputStream(client.getOutputStream());
		}
		catch (IOException e) {
			System.out.println(e);
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
