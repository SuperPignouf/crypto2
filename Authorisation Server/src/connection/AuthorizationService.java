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
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import crypto.RsaKey;

public class AuthorizationService implements Runnable {

	private Socket clientSocket;
	private RsaKey rsaKey;
	private BufferedReader input;
	private PrintWriter output;
	private PublicKey clientPubKey;
	private int ID, clientID;
	private int r1, r2;
	private SecretKey AESBlackboardKey;

	public AuthorizationService(Socket clientSocket, RsaKey rsaKey) {
		this.ID = 0;
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
	}

	@Override
	public void run() {
		try {
			initPipeConnection();
			//printKey();
			sendPubKey();
			receiveClientPubKey();
			needhamSchroeder();
			closeConnection();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		}
	}
	
	private void initPipeConnection() throws IOException {
		this.input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
		this.output = new PrintWriter(new OutputStreamWriter(this.clientSocket.getOutputStream()));
	}
	
	private void sendPubKey() throws IOException {
		System.out.println("PUBLIC KEYS");
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();
		
		System.out.println("SERVER: Public key sent to the client: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	private void receiveClientPubKey() throws IOException, ClassNotFoundException  {
		ObjectInputStream keyIn = new ObjectInputStream(this.clientSocket.getInputStream());
		this.clientPubKey = (PublicKey)keyIn.readObject();

		System.out.println("SERVER: Public key received from the client: " + clientPubKey);
	}

	/**
	 * Needham-Schroeder protocol.
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private void needhamSchroeder() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		System.out.println("\n\nNEEDHAM-SCHROEDER PROTOCOL:");
		System.out.println("RSA:");
		boolean partnerRecognized = false;
		Random randomGenerator = new Random();
		this.r2 = randomGenerator.nextInt(1000000);
		receiveIdAndOnce();
		if (this.clientID == 1){
			sendIdAndOncesToService();
			partnerRecognized = receiveOnceBackFromService();
		}
		//if (partnerRecognized) System.out.println("Server: Partner recognized");
		
		if(this.clientID == 1 && partnerRecognized){
			System.out.println("SERVER: Blackboard fully authentified.");
			System.out.println("\nAES:");
			System.out.println("SERVER: Distribution of the symmetric key...");
			//createAndSendAES();
		}
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
		
		System.out.println("SERVER : ID received from the client: " + this.clientID);
		System.out.println("SERVER : R1 received from the client: " + this.r1);

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
		
		System.out.println("SERVER : ID sent to the blackboard: " + this.ID);
		System.out.println("SERVER : R1 sent to the blackboard: " + this.r1);
		System.out.println("SERVER : R2 sent to the blackboard: " + this.r2);
	}

	private boolean receiveOnceBackFromService() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		SealedObject encryptedR2 = (SealedObject)in.readObject();
		int receivedR2 = (Integer)encryptedR2.getObject(cipher);
		if(this.clientID == 1 && receivedR2 == this.r2) result = true;

		System.out.println("SERVER: R2 received from the client: " + receivedR2);
		return result;
	}
	
	/**
	 * AES
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 */
	private void createAndSendAES() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, BadPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(128);
		this.AESBlackboardKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		//byte[] encryptedAESBlackboardKey = cipher.doFinal(this.AESBlackboardKey.getEncoded());
		
		SealedObject encryptedAESBlackboardKey = new SealedObject(this.AESBlackboardKey, cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedAESBlackboardKey);
		outO.flush();

		System.out.println("SERVER: Blackboard AES key sent.");

	}
	
	/**
	 * Prints the key.
	 */
	private void printKey() {
		System.out.println("SERVER: My keys: " + this.rsaKey.getKeyPair());
		System.out.println("SERVER: My private: " + this.rsaKey.getKeyPair().getPrivate());
		System.out.println("SERVER: My public: " + this.rsaKey.getKeyPair().getPublic());
	}

	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.output.close();
		this.input.close();
		this.clientSocket.close();
	}

}
