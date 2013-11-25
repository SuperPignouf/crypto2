package connection;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.util.Random;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

import crypto.RsaKey;

public class AuthorisationService implements Runnable {

	private Socket clientSocket;
	private RsaKey rsaKey;
	private BufferedReader input;
	private PrintWriter output;
	private PublicKey clientPubKey;
	private int ID, clientID;
	private int r1, r2;

	public AuthorisationService(Socket clientSocket, RsaKey rsaKey) {
		this.ID = 0;
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
	}

	@Override
	public void run() {

		try {

			initConnection();
			sendPubKey();
			receiveClientPubKey();
			needhamSchroeder();
			closeConnection();

		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}

	private void needhamSchroeder() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		boolean partnerRecognized = false;
		Random randomGenerator = new Random();
		this.r2 = randomGenerator.nextInt(1000000);
		receiveIdAndOnce();
		if (this.clientID == 1){
			sendIdAndOncesToService();
			partnerRecognized = receiveOnceBackFromService();
		}
		if (partnerRecognized) System.out.println("Server: Partner recognized");

	}

	private boolean receiveOnceBackFromService() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		SealedObject encryptedR2 = (SealedObject)in.readObject();
		int receivedR2 = (Integer)encryptedR2.getObject(cipher);
		if(this.clientID == 1 && receivedR2 == this.r2) result = true;

		//System.out.println(clientPubKey);
		return result;
	}

	private void sendIdAndOncesToService() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		SealedObject encryptedID = new SealedObject(this.ID, cipher);
		SealedObject encryptedR1 = new SealedObject(this.r1, cipher);
		SealedObject encryptedR2 = new SealedObject(this.r2, cipher);

		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedID);
		outO.flush();
		outO.writeObject(encryptedR1);
		outO.flush();
		outO.writeObject(encryptedR2);
		outO.flush();
	}

	private void receiveIdAndOnce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		SealedObject clientEncryptedID = (SealedObject)in.readObject();
		this.clientID = (Integer)clientEncryptedID.getObject(cipher);
		if(this.clientID == 1){ // Cas du blackboard
			//System.out.println("Server: BlackBoard detected");
			SealedObject EncryptedR1 = (SealedObject)in.readObject();
			this.r1 = (Integer)EncryptedR1.getObject(cipher);
			//System.out.println(r1);
		}

	}

	private void closeConnection() throws IOException {
		this.output.close();
		this.input.close();
		this.clientSocket.close();
	}

	private void receiveClientPubKey() throws IOException, ClassNotFoundException  {

		ObjectInputStream keyIn = new ObjectInputStream(this.clientSocket.getInputStream());
		this.clientPubKey = (PublicKey)keyIn.readObject();

		//System.out.println(clientPubKey);


	}

	private void sendPubKey() throws IOException {
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();

	}

	private void initConnection() throws IOException {
		input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
		this.output = new PrintWriter(new OutputStreamWriter(this.clientSocket.getOutputStream()));

	}

}
