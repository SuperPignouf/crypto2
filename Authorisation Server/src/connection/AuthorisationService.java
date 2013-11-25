package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;

import crypto.RsaKey;

public class AuthorisationService implements Runnable {

	private Socket clientSocket;
	private RsaKey rsaKey;
	private BufferedReader input;
	private PrintWriter output;
	private PublicKey clientPubKey;
	
	public AuthorisationService(Socket clientSocket, RsaKey rsaKey) {
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
	}

	@Override
	public void run() {
		
		initConnection();
		sendPubKey();
		try {
			receiveClientPubKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		closeConnection();
		
		

		
	}

	private void closeConnection() {
		
		try {
			this.output.close();
			this.input.close();
	        this.clientSocket.close();
	        
	     } 
	     catch (IOException e) {
	        System.out.println(e);
	     }
		
	}

	private void receiveClientPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException, ClassNotFoundException {
		try{	
			ObjectInputStream keyIn = new ObjectInputStream(this.clientSocket.getInputStream());
			this.clientPubKey = (PublicKey)keyIn.readObject();
			
			//System.out.println(clientPubKey);
		} catch (IOException e){
			System.out.println("Read failed");
			System.exit(1);
		}
		
		
	}

	private void sendPubKey() {
		try
	    {
	        ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
	        outO.writeObject(this.rsaKey.getKeyPair().getPublic());
	        outO.flush();
	    }
	    catch (Exception ex)
	    {
	        ex.printStackTrace();
	    }
		
	}

	private void initConnection() {
		this.input = null; //Ouverture d'un canal d'entree
		try {
			input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.output = null; //Ouverture d'un canal de sortie
		try {
			this.output = new PrintWriter(new OutputStreamWriter(this.clientSocket.getOutputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
	}

}
