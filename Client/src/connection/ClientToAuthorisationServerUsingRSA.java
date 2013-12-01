package connection;

import java.io.DataInputStream;
import java.io.File;
import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.Certificate;
import java.util.Random;
import java.util.Scanner;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import crypto.RsaKey;

public class ClientToAuthorisationServerUsingRSA {

	private int ID, ASID, WSID, r3, r4, cryptoperiod;
	private RsaKey rsaKey;
	private PublicKey ASPubKey;
	private SecretKey WSClientAESKey;
	private Socket toAS;
	
	
	public ClientToAuthorisationServerUsingRSA(int WSID, RsaKey rsaKey) throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		this.ID = new Scanner(new File("src/ID.txt")).nextInt();
		this.WSID = WSID;
		this.rsaKey = rsaKey;
		
		this.initConnectionWithAS();
		this.receiveASCertificate();
		this.needhamSchroederWithAS();
		this.receiveWSClientAESKey();
		closeConnection();
	}
	
	private void receiveASCertificate() throws IOException, ClassNotFoundException {
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		Certificate AScert = (Certificate)in.readObject();
		if (this.rsaKey.verify(AScert)) this.ASPubKey = AScert.getPublicKey();
		else System.out.println("ERREUR : Certificat de l'AS invalide");
	}
	
	/**
	 * Opens a connection to the Authorisation Server (port 2442).
	 * @throws IOException
	 */
	private void initConnectionWithAS() throws IOException{
		this.toAS = new Socket("localhost", 2442);
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
		SealedObject encryptedR3 = new SealedObject(this.r3, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		outO.writeObject(this.WSID);
		outO.flush();
		outO.writeObject(encryptedID);
		outO.flush();
		outO.writeObject(encryptedWSID);
		outO.flush();
		outO.writeObject(encryptedR3);
		outO.flush();
		
		System.out.println("CLIENT: ID sent to the AS: " + this.ID);
		System.out.println("CLIENT: WSID sent to the AS: " + this.WSID);
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
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getPrivKey());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedASID = (SealedObject) in.readObject();
		SealedObject encryptedWSID = (SealedObject) in.readObject();
		SealedObject encryptedR3 = (SealedObject) in.readObject();
		SealedObject encryptedR4 = (SealedObject) in.readObject();
		this.ASID = (Integer) encryptedASID.getObject(cipher);
		int receivedWSID = (Integer) encryptedWSID.getObject(cipher);
		int receivedR3 = (Integer) encryptedR3.getObject(cipher);
		this.r4 = (Integer) encryptedR4.getObject(cipher);

		if(this.ASID == 0 && receivedWSID == this.WSID && receivedR3 == this.r3)
			result = true;

		System.out.println("CLIENT: AS's ID received from the AS: " + this.ASID);
		System.out.println("CLIENT: WS's ID received from the AS: " + receivedWSID);
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
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getPrivKey());
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
	
	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.toAS.close();
	}
	
	/**
	 * Returns the AS-WS AES session key (to the blackboard's "main" class, ServiceServer).
	 * @return The AS-WS AES session key.
	 */
	public SecretKey getWSClientAESKey() {
		return this.WSClientAESKey;
	}

}
