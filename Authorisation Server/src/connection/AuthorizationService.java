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
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import crypto.RsaKey;

public class AuthorizationService extends Thread implements Runnable {

	private AuthorizationServer AS;
	private Socket clientSocket;
	private RsaKey rsaKey;
	private PublicKey clientPubKey;
	private int ID, clientID, WSID;
	private int r1, r2, r3;
	private SecretKey AESKey;

	public AuthorizationService(Socket clientSocket, RsaKey rsaKey, AuthorizationServer AS) {
		this.AS = AS;
		this.ID = 0;
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
	}

	@Override
	public void run() {
		try {
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
	
	private void sendPubKey() throws IOException { // Envoi cle publique RSA
		System.out.println("PUBLIC KEYS");
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();
		
		System.out.println("AS: Public key sent to the client: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	private void receiveClientPubKey() throws IOException, ClassNotFoundException  { // Reception cle publique RSA
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
		SecureRandom randomGenerator = new SecureRandom();
		this.r2 = randomGenerator.nextInt(1000000);
		receiveIdAndNonce();
		if (this.clientID == 1 || this.clientID == 2){ // c'est un WS
			sendIdAndNoncesToService();
			partnerRecognized = receiveNonceBackFromClient();
		}
		else if (this.clientID > 2){ // C'est un user
			sendIdAndNoncesToUser();
			partnerRecognized = (receiveNonceBackFromClient() && legitimateUser());
		}
		
		
		if(this.clientID == 1 && partnerRecognized){
			System.out.println("AS: Blackboard fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			createAndSendAEStoService();
			this.AS.setBBSessionKey(this.AESKey); // On retient la cle AES pour pouvoir discuter avec le blackboard
		}
		else if(this.clientID == 2 && partnerRecognized){
			System.out.println("AS: KeyChain fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			createAndSendAEStoService();
			this.AS.setKCSessionKey(this.AESKey); // On retient la cle AES pour pouvoir discuter avec le blackboard
		}
		else if(this.clientID > 2 && partnerRecognized){
			System.out.println("AS: User fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			createAndSendAEStoUser();
			this.AS.transmitAESToWS(this.AESKey, this.WSID, this.clientID); // On transfere le clientID et la cle AES au Web service designe par WebServiceID
		}
	}
	

	private void createAndSendAEStoUser() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		this.AESKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		SealedObject encryptedAESKey = new SealedObject(this.AESKey.getEncoded(), cipher);
		SealedObject encryptedR3 = new SealedObject(this.r3, cipher);
		int t = 7200; // cryptoperiode = 2 heures
		SealedObject encryptedT = new SealedObject(t, cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedAESKey);
		outO.writeObject(encryptedT);
		outO.writeObject(encryptedR3);
		outO.flush();

		System.out.println("AS: User AES key sent." + this.AESKey);
		
	}

	private boolean legitimateUser() { // Acces a la bdd + demande eventuelle de mot de passe pour verifier l'identite de l'utilisateur
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
		if(this.clientID == 1 || this.clientID == 2){ // Cas du blackboard ou du keychain
			SealedObject EncryptedR1 = (SealedObject)in.readObject();
			this.r1 = (Integer)EncryptedR1.getObject(cipher);
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
	private void createAndSendAEStoService() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, BadPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		this.AESKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		SealedObject encryptedAESKey = new SealedObject(this.AESKey.getEncoded(), cipher);
		SealedObject encryptedR1 = new SealedObject(this.r1, cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedAESKey);
		outO.writeObject(encryptedR1);
		outO.flush();

		System.out.println("AS: Web Service AES key sent." + this.AESKey);

	}
	

	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.clientSocket.close();
	}

}
