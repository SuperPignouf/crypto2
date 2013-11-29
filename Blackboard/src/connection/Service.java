package connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

public class Service extends Thread implements Runnable {

	private int ID, clientID;
	private Socket clientSocket;
	private SecretKey ASAES;

	public Service(Socket accept, SecretKey aSAESKey) {
		this.ID = 1;
		this.clientSocket = accept;
		this.ASAES = aSAESKey;
	}

	@Override
	public void run() { //Recoit les messages de l'AS et traite les requetes des users
		try {
			this.clientID = identifyClient();
			if (this.clientID == 0){ // AS
				receiveUserIDAndSessionKey();
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}

	private void receiveUserIDAndSessionKey() throws IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		SealedObject encryptedUserID = (SealedObject) in.readObject();
		SealedObject encryptedAESKey = (SealedObject) in.readObject();
		SealedObject encryptedCryptoperiod = (SealedObject) in.readObject();
	}

	private int identifyClient() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		return (Integer) in.readObject();
	}

}
