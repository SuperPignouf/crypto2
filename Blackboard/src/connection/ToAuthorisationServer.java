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
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import crypto.RsaKey;

public class ToAuthorisationServer {

	private Socket toAS;
	private RsaKey rsaKey;
	private PublicKey ASPubKey;
	private int ID, ASID;
	private int r1, r2;
	private SecretKey ASAESKey;
	private ServiceServer SS;

	public 	ToAuthorisationServer(RsaKey rsaKey) throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException{
		this.ID = 1;
		this.rsaKey = rsaKey;
		initConnection();
		sendPubKey();
		receiveASPubKey();
		needhamSchroeder();
		closeConnection();
	}

	private void initConnection() throws IOException{
		toAS = new Socket("localhost", 2442);
	}
	
	private void sendPubKey() throws IOException {
		System.out.println("PUBLIC KEYS");
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.rsaKey.getKeyPair().getPublic());
		outO.flush();
		
		System.out.println("BLACKBOARD: Public key sent to the authorization server: " + this.rsaKey.getKeyPair().getPublic());
	}
	
	private void receiveASPubKey() throws IOException, ClassNotFoundException {

		ObjectInputStream keyIn = new ObjectInputStream(this.toAS.getInputStream());
		this.ASPubKey = (PublicKey)keyIn.readObject();
		
		System.out.println("BLACKBOARD: Public key received from the server: " + this.ASPubKey);
	}
	
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
			receiveAESSessionKey();
		}
	}
	
	private void receiveAESSessionKey() throws IOException, ClassNotFoundException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject encryptedSessionKey = (SealedObject)in.readObject();
		SealedObject encryptedR1 = (SealedObject)in.readObject();
		if ((Integer)encryptedR1.getObject(cipher) == this.r1){
			byte[] SessionKey = new byte[32];
			SessionKey = (byte[]) encryptedSessionKey.getObject(cipher);
			this.ASAESKey = new SecretKeySpec(SessionKey, 0, 32, "AES");
			this.SS.setASAES(this.ASAESKey);
			System.out.println("BB : received AES key (AS-BB)" + this.ASAESKey);
		}
		else System.out.println("BB : error: bad r1, AES key refused");

		
	}

	private void sendIdAndNonce() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedR1 = new SealedObject(this.r1, cipher);
		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(this.ID);
		outO.flush();
		outO.writeObject(encryptedR1);
		outO.flush();
		
		System.out.println("BLACKBOARD: ID sent to the AS: " + this.ID);
		System.out.println("BLACKBOARD: R1 sent to the AS: " + this.r1);
	}
	
	private boolean receiveIdAndNonceFromAS() throws IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, ClassNotFoundException {
		boolean result = false;
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.DECRYPT_MODE, this.rsaKey.getKeyPair().getPrivate());
		ObjectInputStream in = new ObjectInputStream(this.toAS.getInputStream());
		SealedObject ASEncryptedID = (SealedObject)in.readObject();
		SealedObject EncryptedR1 = (SealedObject)in.readObject();
		SealedObject EncryptedR2 = (SealedObject)in.readObject();
		this.ASID = (Integer)ASEncryptedID.getObject(cipher);
		int receivedR1 = (Integer)EncryptedR1.getObject(cipher);
		this.r2 = (Integer)EncryptedR2.getObject(cipher);

		if(this.ASID == 0 && receivedR1 == this.r1)result = true; //System.out.println("Client: serveur d'authentification authentifie");

		System.out.println("BLACKBOARD: ID received from the AS: " + this.ASID);
		System.out.println("BLACKBOARD: R1 received from the AS: " + receivedR1);
		System.out.println("BLACKBOARD: R2 received from the AS: " + this.r2);
		return result;
	}

	private void sendNonceBack() throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, IOException {
		Cipher cipher = Cipher.getInstance("RSA");
		cipher.init(Cipher.ENCRYPT_MODE, this.ASPubKey);
		SealedObject encryptedR2 = new SealedObject(this.r2, cipher);

		ObjectOutputStream outO = new ObjectOutputStream(this.toAS.getOutputStream());
		outO.writeObject(encryptedR2);
		outO.flush();
		
		System.out.println("BLACKBOARD: R2 sent to the AS: " + this.r2);
	}

	/**
	 * Closes the connection.
	 * @throws IOException
	 */
	private void closeConnection() throws IOException {
		this.toAS.close();
	}

	public SecretKey getASAESKey() {
		return this.ASAESKey;
	}

}
