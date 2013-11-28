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

	private AuthorizationServer AS;
	private Socket clientSocket;
	private RsaKey rsaKey;
	private BufferedReader input;
	private PrintWriter output;
	private PublicKey clientPubKey;
	private int ID, clientID, WSID;
	private int r1, r2, r3;
	private SecretKey AESServiceKey;

	public AuthorizationService(Socket clientSocket, RsaKey rsaKey, AuthorizationServer AS) {
		this.AS = AS;
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
		
		System.out.println("AS: Public key sent to the client: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	private void receiveClientPubKey() throws IOException, ClassNotFoundException  {
		ObjectInputStream keyIn = new ObjectInputStream(this.clientSocket.getInputStream());
		this.clientPubKey = (PublicKey)keyIn.readObject();

		System.out.println("AS: Public key received from the client: " + clientPubKey);
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
		receiveIdAndNonce();
		if (this.clientID == 1){
			sendIdAndNoncesToService();
			partnerRecognized = receiveNonceBackFromClient();
		}
		else if (this.clientID > 2){
			sendIdAndNoncesToUser();
			partnerRecognized = (receiveNonceBackFromClient() && legitimateUser());
		}
		
		
		if(this.clientID == 1 && partnerRecognized){
			System.out.println("AS: Blackboard fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			createAndSendAES();
			//this.AS.setBBSessionKey(this.AESServiceKey);
		}
		else if(this.clientID > 2 && partnerRecognized){
			System.out.println("AS: User fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			//createAndSendAES();
		}
	}
	

	private boolean legitimateUser() {
		// Cette methode va aller voir dans la base de donnees si le user qui tente la connexion est bien enregistre.
		return true;
	}

	private void sendIdAndNoncesToUser() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		SealedObject encryptedID = new SealedObject(this.ID, cipher);
		SealedObject encryptedWSID = new SealedObject(this.WSID, cipher);
		SealedObject encryptedR3 = new SealedObject(this.r3, cipher);
		SealedObject encryptedR2 = new SealedObject(this.r2, cipher);

		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedID);
		outO.flush();
		outO.writeObject(encryptedWSID);
		outO.flush();
		outO.writeObject(encryptedR3);
		outO.flush();
		outO.writeObject(encryptedR2);
		outO.flush();
		
		System.out.println("AS: ID sent to the blackboard: " + this.ID);
		System.out.println("AS: WSID sent to the blackboard: " + this.ID);
		System.out.println("AS: R3 sent to the blackboard: " + this.r3);
		System.out.println("AS: R4 sent to the blackboard: " + this.r2);
		
	}

	private void receiveIdAndNonce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
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
			System.out.println("AS: ID received from the client: " + this.clientID);
			System.out.println("AS: R1 received from the client: " + this.r1);
		}
		else if(this.clientID > 2){ // Cas d'un utilisateur
			SealedObject EncryptedWSID = (SealedObject)in.readObject();
			this.WSID = (Integer)EncryptedWSID.getObject(cipher);
			SealedObject EncryptedR3 = (SealedObject)in.readObject();
			this.r3 = (Integer)EncryptedR3.getObject(cipher);
			
			System.out.println("AS: ID received from the client: " + this.clientID);
			System.out.println("AS: R3 received from the client: " + this.r3);
			System.out.println("AS: Required WS: " + this.WSID);
		}
	}
	
	private void sendIdAndNoncesToService() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
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
		
		System.out.println("AS: ID sent to the blackboard: " + this.ID);
		System.out.println("AS: R1 sent to the blackboard: " + this.r1);
		System.out.println("AS: R2 sent to the blackboard: " + this.r2);
	}

	private boolean receiveNonceBackFromClient() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		SealedObject encryptedR2 = (SealedObject)in.readObject();
		int receivedR2 = (Integer)encryptedR2.getObject(cipher);
		if(receivedR2 == this.r2) result = true;

		System.out.println("AS: R2 received from the client: " + receivedR2);
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
		this.AESServiceKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		//byte[] encryptedAESBlackboardKey = cipher.doFinal(this.AESBlackboardKey.getEncoded());
		
		//this.AESServiceKey.
		SealedObject encryptedAESServiceKey = new SealedObject(this.AESServiceKey.getEncoded(), cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedAESServiceKey);
		outO.flush();

		System.out.println("AS: Blackboard AES key sent.");

	}
	
	/**
	 * Prints the key.
	 */
	private void printKey() {
		System.out.println("AS: My keys: " + this.rsaKey.getKeyPair());
		System.out.println("AS: My private: " + this.rsaKey.getKeyPair().getPrivate());
		System.out.println("AS: My public: " + this.rsaKey.getKeyPair().getPublic());
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
