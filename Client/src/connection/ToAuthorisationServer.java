package connection;

import java.io.DataInputStream;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import crypto.RsaKey;

public class ToAuthorisationServer {

	private int ID, ASID, WSID, r3, r4, cryptoperiod;
	private RsaKey rsaKey;
	private PublicKey ASPubKey;
	private SecretKey WSClientAESKey;
	private Socket toAS, toWS1, toWS2;
	
	public ToAuthorisationServer(int WSID, RsaKey rsaKey) throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		// TODO Need to modify the creation of the ID.
		Random randGenerator = new Random(999997);
		this.ID = randGenerator.nextInt() + 3;
		this.WSID = WSID;
		this.rsaKey = rsaKey;
		
		this.initConnectionWithAS();
		this.sendPubKey();
		this.receiveASPubKey();
		this.needhamSchroederWithAS();
		// TODO Need to verify of the verifications associated the Needham-Schroeder protocol succeeded
		// and that the Client can have access to the asked service.
		this.receiveWSClientAESKey();
		//closeConnection();
	}
	
	/**
	 * Opens a connection to the Authorisation Server (port 2442).
	 * @throws IOException
	 */
	private void initConnectionWithAS() throws IOException{
		this.toAS = new Socket("localhost", 2442);
	}
	
	/**
	 * Opens a connection to the first Web Service (virtual blackboard, port 4224).
	 * @throws IOException
	 */
	private void initConnectionWithWS1() throws IOException{
		this.toWS1 = new Socket("localhost", 4224);
	}
	
	/**
	 * Opens a connection to the second Web Service (virtual keychain server, port 4224).
	 * @throws IOException
	 */
	private void initConnectionWithWS2() throws IOException{
		this.toWS2 = new Socket("localhost", 4242);
	}
	
	// TODO It's the admin who must generate the keys.
	private void sendPubKey() throws IOException {
		System.out.println("PUBLIC KEYS");
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();
		
		System.out.println("CLIENT: Public key sent to the authorization server: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	// TODO It's the admin who must generate the keys.
	private void receiveASPubKey() throws IOException, ClassNotFoundException {

		ObjectInputStream keyIn = new ObjectInputStream(this.toAS.getInputStream());
		this.ASPubKey = (PublicKey) keyIn.readObject();
		
		System.out.println("CLIENT: Public key received from the server: " + this.ASPubKey);
	}
	
	/**
	 * Launches a Needham-Schroeder protocol between the Client and the AS. 
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 * @throws BadPaddingException
	 * @throws ClassNotFoundException
	 */
	private void needhamSchroederWithAS() throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, ClassNotFoundException {
		System.out.println("\n\nNEEDHAM-SCHROEDER PROTOCOL:");
		System.out.println("RSA:");
		boolean ASRecognized = false;
		SecureRandom randomGenerator = new SecureRandom();
		this.r3 = randomGenerator.nextInt(1000000);
		sendIDsAndNonce();
		ASRecognized = receiveIDsAndNoncesFromAS();
		if(ASRecognized) {
			sendNonceBack();
		}
	}
	
	/**
	 * First part of the Needham-Schroeder protocol for the Client, sends the Client and the WS's IDs as well as the nonce to the AS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private void sendIDsAndNonce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedID = new SealedObject(this.ID, cipher);
		SealedObject encryptedWSID = new SealedObject(this.WSID, cipher);
		SealedObject encryptedR1 = new SealedObject(this.r3, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		outO.writeObject(this.WSID);
		outO.flush();
		outO.writeObject(encryptedID);
		outO.flush();
		outO.writeObject(encryptedWSID);
		outO.flush();
		outO.writeObject(encryptedR1);
		outO.flush();
		
		System.out.println("CLIENT: ID sent to the AS: " + this.ID);
		System.out.println("CLIENT: ID sent to the AS: " + this.WSID);
		System.out.println("CLIENT: R3 sent to the AS: " + this.r3);
	}
	
	/**
	 * Second part of the Needham-Schroeder protocol for the Client, receives the AS and the WS's IDs as well as the nonces from the AS.
	 * @throws ClassNotFoundException 
	 * @throws IOException 
	 * @throws BadPaddingException 
	 * @throws IllegalBlockSizeException 
	 * @throws InvalidKeyException 
	 * @throws NoSuchPaddingException 
	 * @throws NoSuchAlgorithmException 
	 */
	private boolean receiveIDsAndNoncesFromAS() throws IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedASID = (SealedObject) in.readObject();
		SealedObject encryptedWSID = (SealedObject) in.readObject();
		SealedObject encryptedR3 = (SealedObject) in.readObject();
		SealedObject encryptedR4 = (SealedObject) in.readObject();
		this.ASID = (Integer) encryptedASID.getObject(cipher);
		int receivedWSID = (Integer) encryptedWSID.getObject(cipher);
		int receivedR3 = (Integer) encryptedR3.getObject(cipher);
		this.r4 = (Integer) encryptedR4.getObject(cipher);

		if(this.ASID == 0 && receivedWSID == this.WSID && receivedR3 == this.r4)
			result = true;

		System.out.println("CLIENT: AS's ID received from the AS: " + this.ASID);
		System.out.println("CLIENT: WS's ID received from the AS: " + receivedR3);
		System.out.println("CLIENT: R3 received from the AS: " + receivedR3);
		System.out.println("CLIENT: R4 received from the AS: " + this.r4);
		return result;
	}
	
	/**
	 * Third and last part of the Needham-Schroeder protocol for the Client, sends back the second nouce to the AS.
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws InvalidKeyException
	 * @throws IllegalBlockSizeException
	 * @throws IOException
	 */
	private void sendNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedR4 = new SealedObject(this.r4, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(encryptedR4);
		outO.flush();
		
		System.out.println("CLIENT: R4 sent to the AS: " + this.r4);
	}
	
	/**
	 * Receives from the AS the WS-Client AES session key used by the client to send encrypted requests to the asked WS.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 */
	private void receiveWSClientAESKey() throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedSessionKey = (SealedObject) in.readObject();
		SealedObject encryptedCryptoperiod = (SealedObject) in.readObject();
		SealedObject encryptedR3 = (SealedObject) in.readObject();
		if ((Integer) encryptedR3.getObject(cipher) == this.r3) {
			this.cryptoperiod = (Integer) encryptedCryptoperiod.getObject(cipher);
			byte[] SessionKey = new byte[32];
			SessionKey = (byte[]) encryptedSessionKey.getObject(cipher);
			this.WSClientAESKey = new SecretKeySpec(SessionKey, 0, 32, "AES"); // AES key shared between the WS and the Client.
			System.out.println("CLIENT: received AES key (Client-WS)" + this.WSClientAESKey);
		}
		else
			System.out.println("CLIENT: error: bad r2, AES key refused");
	}

}
