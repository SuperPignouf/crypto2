package connection;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import dataContainers.IDAES;

public class BlackboardAESSecuredService extends Thread implements Runnable {

	private int ID, clientID, userID; // personal ID, any client's ID (AS ou user), user's ID.
	private Socket clientSocket;
	private SecretKey ASKey; // La cle de session AES permettant de communiquer avec l'AS
	private BlackboardWebService blackboard;

	public BlackboardAESSecuredService(BlackboardWebService blackboard, Socket accept, SecretKey ASAESKey) {
		this.ID = 1;
		this.clientSocket = accept;
		this.ASKey = ASAESKey;
		this.blackboard = blackboard;
	}
	
	/**
	 * Receives messages from the AS and requests from User
	 */
	@Override
	public void run() {
		try {
			identifyClient();
			if (this.clientID == 0){ // AS
				System.out.println("BLACKBOARD : AS identified");
				receiveUserIDAndBlackboardUserKey();
			}
			else if (this.clientID > 2 && this.clientID == this.userID){ // Expected user
				System.out.println("BLACKBOARD : user identified");
				runService(this.blackboard.getIDAES(this.clientID));
			}
		} catch (IOException e) {
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			e.printStackTrace();
		} catch (BadPaddingException e) {
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			e.printStackTrace();
		}
		
	}
	
	private void runService(IDAES idaes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, idaes.getAES());
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		
		String msg = "Bonjour client, je suis un Blackboard";
		SealedObject encryptedMsg = new SealedObject (msg, cipher);
		outO.writeObject(encryptedMsg);
		outO.flush();
		
	}

	private void receiveUserIDAndBlackboardUserKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, this.ASKey);
		System.out.println(this.clientSocket.getInputStream());
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		SealedObject encryptedUserID = (SealedObject) in.readObject();
		SealedObject encryptedClientKey = (SealedObject) in.readObject();
		SealedObject encryptedCryptoperiod = (SealedObject) in.readObject();
		this.userID = (Integer) encryptedUserID.getObject(cipher);
		byte[] userKey = new byte[32];
		userKey = (byte[]) encryptedClientKey.getObject(cipher);
		this.blackboard.addIDAES((Integer) encryptedUserID.getObject(cipher), (Integer) encryptedCryptoperiod.getObject(cipher), new SecretKeySpec(userKey, 0, 32, "AES")); // L'id de l'user et la cle associee sont stockees dans l'objet serviceServer
		
		System.out.println("BLACKBOARD : received user ID : " + this.userID);
		System.out.println("BLACKBOARD : received related session AES key : " + new SecretKeySpec(userKey, 0, 32, "AES"));
		System.out.println("BLACKBOARD : received cryptoperiod of that key : " + (Integer) encryptedCryptoperiod.getObject(cipher) + "sec");
	}

	private void identifyClient() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		this.clientID = (Integer) in.readObject();
	}

}
