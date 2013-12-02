package connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;

import crypto.RsaKey;
import dataBase.DbLink;

/**
 * Class for connecting to Clients (WS or user) using RSA encryption.
 */
public class RSASecuredService extends Thread implements Runnable {

	private AuthorisationServer AS;
	private Socket clientSocket;
	private RsaKey rsaKey;
	private PublicKey clientPubKey;
	private int ID, clientID, WSID; // AS"s ID, Client's ID and ID of the WS asked by the client (when the Client is a user)
	private int r1, r2, r3; // TODO r2 = r4 OK ?
	private int cryptoperiod;
	private SecretKey ASWSAESKey, WSClientAESKey;
	private DbLink dbLink;
	
	public RSASecuredService(AuthorisationServer AS, Socket clientSocket, RsaKey rsaKey, int ID, int cryptoperiod, DbLink dbLink) {

		this.AS = AS;
		this.ID = ID;
		this.cryptoperiod = cryptoperiod;
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
		this.dbLink = dbLink;
	}

	@Override
	public void run() {
		try {
			sendCertificate();
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
		} catch (CertificateException e) {
			e.printStackTrace();
		}
	}
	
	private void sendCertificate() throws IOException, CertificateEncodingException {
		System.out.println("AS CERTIFICATE");
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(this.rsaKey.getCert());
		outO.flush();
		
		System.out.println("AS: Certificate sent to the client: " + this.rsaKey.getCert());
		
	}
	

	/**
	 * Launches a Needham-Schroeder protocol between the Client (WS or user) and the AS. 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CertificateException 
	 */
	private void needhamSchroeder() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException, CertificateException {
		System.out.println("\n\nNEEDHAM-SCHROEDER PROTOCOL:");
		System.out.println("RSA:");
		boolean partnerRecognized = false;
		SecureRandom randomGenerator = new SecureRandom();
		this.r2 = randomGenerator.nextInt(1000000);
		receiveIdAndNonce();
		if (this.clientID == 1 || this.clientID == 2){ // If WS.
			sendIdAndNoncesToService();
			partnerRecognized = receiveNonceBack();
		}
		else if (this.clientID > 2){ // If User.
			sendIdAndNoncesToUser();
			partnerRecognized = receiveNonceBack();
		}
		
		// TODO The following lines of code should be moved in another function keysDistribution for example.
		if(this.clientID == 1 && partnerRecognized){ // If the Client is the Blackboard.
			System.out.println("AS: Blackboard fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key AS-WS to the blackboard...");
			createAndSendASWSAESKeyToService();
			this.AS.setASBlackboardAESKey(this.ASWSAESKey); // The AS-WS AES Key is memorized by the AS.
		}
		else if(this.clientID == 2 && partnerRecognized){ // If the Client is the Keychain.
			System.out.println("AS: KeyChain fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key AS-WS to the keychain...");
			createAndSendASWSAESKeyToService();
			this.AS.setASKeychainAESKey(this.ASWSAESKey); // The AS-WS AES Key is memorized by the AS.
		}
		else if(this.clientID > 2 && partnerRecognized){ // If the Client is a user.
			System.out.println("AS: User fully authentified.");
			System.out.println("\nAES:");
			System.out.println("AS: Distribution of the symmetric key...");
			try {
				createAndSendWSClientAESKeyToUser();
			} catch (InterruptedException e) {
				e.printStackTrace();
			}
		}
	}
	
	/**
	 * First part of the Needham-Schroeder protocol for the AS, receives the Client's ID (WS or user) as well as a nonce.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws CertificateException 
	 */
	private void receiveIdAndNonce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException, CertificateException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getPrivKey());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		this.clientID = (Integer) in.readObject(); // First ID that the AS receives.
		this.clientPubKey = this.dbLink.getCertificateByUserID(this.clientID).getPublicKey();
		if (this.clientPubKey == null) System.out.println("ERREUR : l'ID " + this.clientID + " n'est pas reconnue");
		if(this.clientID == 1 || this.clientID == 2) { // When the Client is a Web Service (blackboard or keychain).
			SealedObject encryptedWSID = (SealedObject) in.readObject();
			SealedObject encryptedR1 = (SealedObject) in.readObject();
			this.r1 = (Integer) encryptedR1.getObject(cipher);
			System.out.println("AS: ID received from the client (WS): " + this.clientID);
			System.out.println("AS: R1 received from the client: " + this.r1);
		}
		else if(this.clientID > 2){ // When the Client is a user.
			this.WSID = (Integer) in.readObject();
			SealedObject encryptedClientID = (SealedObject) in.readObject();
			SealedObject encryptedWSID = (SealedObject) in.readObject();
			SealedObject encryptedR3 = (SealedObject) in.readObject();
			this.r3 = (Integer) encryptedR3.getObject(cipher);
			
			System.out.println("AS: ID received from the client (user): " + this.clientID);
			System.out.println("AS: Required WS: " + this.WSID);
			System.out.println("AS: R3 received from the client (user): " + this.r3);
		}
	}
	
	/**
	 * Second part of the Needham-Schroeder protocol for the AS when the Client is a Web Service. It sends the AS's ID and two nonces.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
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
	
	/**
	 * Second part of the Needham-Schroeder protocol for the AS when the Client is a user. It sends the AS's and the asked WS's IDs and two nonces.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
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
		
		System.out.println("AS: ID sent to the client: " + this.ID);
		System.out.println("AS: WSID sent to the client: " + this.WSID);
		System.out.println("AS: R3 sent to the client: " + this.r3);
		System.out.println("AS: R4 sent to the client: " + this.r2);
		
	}
	
	/**
	 * Third and last part of the Needham-Schroeder protocol for the AS, receives the second nouce from the Client (WS or user).
	 * @return
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws IOException
	 * @throws ClassNotFoundException
	 */
	private boolean receiveNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		//cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getPrivKey());
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getPrivKey());

		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());

		SealedObject encryptedR2 = (SealedObject) in.readObject();
		int receivedR2 = (Integer) encryptedR2.getObject(cipher);
		if(receivedR2 == this.r2)
			result = true;
		
		System.out.println("AS: R2 received from the client: " + receivedR2);
		return result;
	}
	
	/**
	 * Generates the AS-WS AES session key for the WS that will be used to decrypt the Client-WS "cryptoperiodic" AES session key later sent to the WS by the AS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 */
	private void createAndSendASWSAESKeyToService() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, BadPaddingException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		this.ASWSAESKey = keyGen.generateKey();

		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		SealedObject encryptedAESKey = new SealedObject(this.ASWSAESKey.getEncoded(), cipher);
		SealedObject encryptedR1 = new SealedObject(this.r1, cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedAESKey);
		outO.flush();
		outO.writeObject(encryptedR1);
		outO.flush();

		System.out.println("AS: Web Service AES key sent: " + this.ASWSAESKey);

	}
	
	/**
	 * Generates the WS-Client AES "cryptoperiodic" session key for the user that will be used to send encrypted requests to the asked WS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws InvalidKeyException
	 * @throws InterruptedException 
	 */
	private void createAndSendWSClientAESKeyToUser() throws NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, InvalidKeyException, InterruptedException {
		KeyGenerator keyGen = KeyGenerator.getInstance("AES");
		keyGen.init(256);
		this.WSClientAESKey = keyGen.generateKey();
		
		this.AS.transmitWSClientAESKeyToWS(this.WSClientAESKey, this.WSID, this.clientID);
		sleep(3000);
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.clientPubKey);
		
		SealedObject encryptedWSClientAESKey = new SealedObject(this.WSClientAESKey.getEncoded(), cipher);
		SealedObject encryptedR3 = new SealedObject(this.r3, cipher);
		SealedObject encryptedCryptoperiod = new SealedObject(this.cryptoperiod, cipher);
		
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		outO.writeObject(encryptedWSClientAESKey);
		outO.flush();
		outO.writeObject(encryptedCryptoperiod);
		outO.flush();
		outO.writeObject(encryptedR3);
		outO.flush();

		System.out.println("AS: User AES key sent: " + this.WSClientAESKey);
		
	}

	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.clientSocket.close();
	}

}
