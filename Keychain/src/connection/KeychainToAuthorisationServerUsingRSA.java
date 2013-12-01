package connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import crypto.RsaKey;

/**
 * Class for connecting to the Authorisation Server and receiving at the end the AS-Keychain AES session key.
 */
public class KeychainToAuthorisationServerUsingRSA {

	private KeychainWebService keychain;
	private Socket toAS;
	private RsaKey rsaKey;
	private PublicKey ASPubKey;
	private int ID, ASID;
	private int r1, r2;
	private SecretKey ASKeychainAESKey;
	
	/**
	 * Constructor : initializes the ID and launches the whole protocol for the Keychain.
	 * @param ID
	 * @param rsaKey
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	public 	KeychainToAuthorisationServerUsingRSA(KeychainWebService keychain, int ID, RsaKey rsaKey) throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		this.keychain = keychain;
		this.ID = ID;
		this.rsaKey = rsaKey;
		initConnection();
		sendPubKey();
		receiveASPubKey();
		needhamSchroeder();
		receiveASKeychainAESKey();
		closeConnection();
	}

	private void initConnection() throws IOException{
		toAS = new Socket("localhost", 2442);
	}
	
	// TODO It's the admin who must generate the keys.
	private void sendPubKey() throws IOException {
		System.out.println("PUBLIC KEYS");
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();
		
		System.out.println("KEYCHAIN: Public key sent to the authorisation server: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	// TODO It's the admin who must generate the keys.
	private void receiveASPubKey() throws IOException, ClassNotFoundException {

		ObjectInputStream keyIn = new ObjectInputStream(this.toAS.getInputStream());
		this.ASPubKey = (PublicKey) keyIn.readObject();
		
		System.out.println("KEYCHAIN: Public key received from the server: " + this.ASPubKey);
	}
	
	/**
	 * Launches a Needham-Schroeder protocol between the Keychain and the AS. 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws ClassNotFoundException
	 */
	private void needhamSchroeder() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, ClassNotFoundException {
		System.out.println("\n\nNEEDHAM-SCHROEDER PROTOCOL:");
		System.out.println("RSA:");
		boolean ASRecognized = false;
		SecureRandom randomGenerator = new SecureRandom();
		this.r1 = randomGenerator.nextInt(1000000);
		sendIdAndNonce();
		ASRecognized = receiveIdAndNonceFromAS();
		if(ASRecognized) {
			sendNonceBack();
		}
	}
	
	/**
	 * First part of the Needham-Schroeder protocol for the Keychain, sends the Keychain's ID as well as the nonce to the AS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private void sendIdAndNonce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedID = new SealedObject(this.ID, cipher);
		SealedObject encryptedR1 = new SealedObject(this.r1, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		outO.writeObject(encryptedID);
		outO.flush();
		outO.writeObject(encryptedR1);
		outO.flush();
		
		System.out.println("KEYCHAIN: ID sent to the AS: " + this.ID);
		System.out.println("KEYCHAIN: R1 sent to the AS: " + this.r1);
	}
	
	/**
	 * Second part of the Needham-Schroeder protocol for the Keychain, receives the AS's ID as well as the nonces from the AS.
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	private boolean receiveIdAndNonceFromAS() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedASID = (SealedObject) in.readObject();
		SealedObject encryptedR1 = (SealedObject) in.readObject();
		SealedObject encryptedR2 = (SealedObject) in.readObject();
		this.ASID = (Integer) encryptedASID.getObject(cipher);
		int receivedR1 = (Integer) encryptedR1.getObject(cipher);
		this.r2 = (Integer) encryptedR2.getObject(cipher);

		if(this.ASID == 0 && receivedR1 == this.r1)
			result = true; //System.out.println("Client: serveur d'authentification authentifie");

		System.out.println("KEYCHAIN: ID received from the AS: " + this.ASID);
		System.out.println("KEYCHAIN: R1 received from the AS: " + receivedR1);
		System.out.println("KEYCHAIN: R2 received from the AS: " + this.r2);
		return result;
	}
	
	/**
	 * Third and last part of the Needham-Schroeder protocol for the Keychain, sends back the second nouce to the AS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private void sendNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedR2 = new SealedObject(this.r2, cipher);

		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(encryptedR2);
		outO.flush();
		
		System.out.println("KEYCHAIN: R2 sent to the AS: " + this.r2);
	}
	
	/**
	 * Receives from the AS the AS-Keychain AES session key that will be used by the Keychain to decrypt the Client-Keychain "cryptoperiodic" AES session key later sent by the AS.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private void receiveASKeychainAESKey() throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedSessionKey = (SealedObject) in.readObject();
		SealedObject encryptedR1 = (SealedObject) in.readObject();
		if ((Integer) encryptedR1.getObject(cipher) == this.r1){
			byte[] SessionKey = new byte[32];
			SessionKey = (byte[]) encryptedSessionKey.getObject(cipher);
			this.ASKeychainAESKey = new SecretKeySpec(SessionKey, 0, 32, "AES");
			this.keychain.setASKeychainAES(ASKeychainAESKey);
			System.out.println("KEYCHAIN : received AS-Keychain AES session key: " + this.ASKeychainAESKey);
		}
		else
			System.out.println("KEYCHAIN : error: wrong r1, AS-Keychain AES session key refused");
	}

	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.toAS.close();
	}
	
	/**
	 * Returns the AS-Keychain AES session key (to the Keychain's "main" class, ServiceServer).
	 * @return The AS-Keychain AES session key.
	 */
	public SecretKey getASKeychainAESKey() {
		return this.ASKeychainAESKey;
	}

}
