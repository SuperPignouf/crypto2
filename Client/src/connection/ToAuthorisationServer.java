package connection;

import java.io.DataInputStream;
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

		DataInputStream input;
		try {
			input = new DataInputStream(client.getInputStream());
		}
		catch (IOException e) {
			System.out.println(e);
		}

	}

}
