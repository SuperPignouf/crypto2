package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PublicKey;

import crypto.RsaKey;

public class ToAuthorisationServer {
	
	private Socket toAS;
	private BufferedReader input;
	private PrintWriter output;
	private RsaKey rsaKey;
	private PublicKey ASPubKey;

	public 	ToAuthorisationServer(RsaKey rsaKey){
		
		this.rsaKey = rsaKey;
		initConnection();
		sendPubKey();
		receiveASPubKey();
		closeConnection();

		//printKeys();
	}
	
	private void printKeys() {
		System.out.println("AS: " + this.ASPubKey);
		System.out.println("BB: " + this.rsaKey.getKeyPair());
		
	}

	private void closeConnection() {
		try {
			this.output.close();
			this.input.close();
			this.toAS.close();
		} 
		catch (IOException e) {
			System.out.println(e);
		}
		
	}

	private void receiveASPubKey() {
		//System.out.println("CLIENT: Attente de reception de cle RSA publique.");
		try{	
			ObjectInputStream keyIn = new ObjectInputStream(this.toAS.getInputStream());
			this.ASPubKey = (PublicKey)keyIn.readObject();
		} catch (IOException e){
			System.out.println("Read failed");
			System.exit(1);
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
		
	}

	private void sendPubKey() {
		
		try
	    {
	        ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
	        outO.writeObject(this.rsaKey.getKeyPair().getPublic());
	        outO.flush();
	    }
	    catch (Exception ex)
	    {
	        ex.printStackTrace();
	    }
		
		
	}

	private void initConnection(){
		this.toAS = null;
		try {
			toAS = new Socket("localhost", 2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.input = null;
		try {
			this.input = new BufferedReader(new InputStreamReader(this.toAS.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.output = null; //Ouverture d'un canal de sortie
		try {
			this.output = new PrintWriter(new OutputStreamWriter(this.toAS.getOutputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}
	}

}
