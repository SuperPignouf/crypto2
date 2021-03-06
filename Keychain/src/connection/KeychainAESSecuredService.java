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

import dataBase.DbLink;
import dataContainers.IDAES;

public class KeychainAESSecuredService extends Thread implements Runnable {

	private int clientID; // personal ID, any client's ID (AS ou user).
	private Socket clientSocket;
	private SecretKey ASKey; // La cle de session AES permettant de communiquer avec l'AS
	private KeychainWebService keychain;
	private ObjectInputStream in;
	private ObjectOutputStream outO;
	private DbLink dbLink=null;

	public KeychainAESSecuredService(KeychainWebService keychain, Socket accept, SecretKey ASAESKey, DbLink dblink) {
		this.clientSocket = accept;
		this.ASKey = ASAESKey;
		this.keychain = keychain;
		this.dbLink=dblink;
	}
	
	/**
	 * Receives messages from the AS and requests from User
	 */
	@Override
	public void run() {
		try {
			this.in = new ObjectInputStream(this.clientSocket.getInputStream());
			this.outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
			identifyClient();
			if (this.clientID == 0){ // AS
				System.out.println("KEYCHAIN : AS identified");
				receiveUserIDAndKeychainUserKey();
			}
			else if (this.clientID > 2 && this.clientID == this.keychain.getUserID()){ // Expected user
				System.out.println("KEYCHAIN : user identified");
				runService(this.keychain.getIDAES(this.clientID));
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
	
	private void runService(IDAES idaes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException, BadPaddingException, ClassNotFoundException{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, idaes.getAES());
		//ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		
		String msg = "Bonjour client, je suis un Keychain";
		SealedObject encryptedMsg = new SealedObject (msg, cipher);
		outO.writeObject(encryptedMsg);
		outO.flush();
		
		System.out.println("\n"+"------- KEYCHAIN -------");
		cipher.init(Cipher.DECRYPT_MODE, idaes.getAES());
		while(!msg.equals(" ")) { //TODO add cryptotime
			this.in = new ObjectInputStream(this.clientSocket.getInputStream());
			SealedObject ClientMsg = (SealedObject) in.readObject();
			msg = (String) ClientMsg.getObject(cipher);
			System.out.println(msg);
			this.dbLink.insertData(this.clientID, "login", msg);
		}
		System.out.println("END");
		
	}

	private void receiveUserIDAndKeychainUserKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, this.ASKey);
		//ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		SealedObject encryptedUserID = (SealedObject) this.in.readObject();
		SealedObject encryptedClientKey = (SealedObject) this.in.readObject();
		SealedObject encryptedCryptoperiod = (SealedObject) this.in.readObject();
		this.keychain.setUserID((Integer) encryptedUserID.getObject(cipher));
		byte[] userKey = new byte[32];
		userKey = (byte[]) encryptedClientKey.getObject(cipher);
		this.keychain.addIDAES((Integer) encryptedUserID.getObject(cipher), (Integer) encryptedCryptoperiod.getObject(cipher), new SecretKeySpec(userKey, 0, 32, "AES")); // L'id de l'user et la cle associee sont stockees dans l'objet serviceServer
		
		System.out.println("KEYCHAIN : received user ID : " + this.keychain.getUserID());
		System.out.println("KEYCHAIN : received related session AES key : " + new SecretKeySpec(userKey, 0, 32, "AES"));
		System.out.println("KEYCHAIN : received cryptoperiod of that key : " + (Integer) encryptedCryptoperiod.getObject(cipher) + "sec");
	}

	/**
	 * Identifies the client.
	 * @throws IOException
	 * @throws ClassNotFoundException
	 * @throws IllegalBlockSizeException
	 * @throws BadPaddingException
	 * @throws InvalidKeyException
	 * @throws NoSuchAlgorithmException
	 * @throws NoSuchPaddingException
	 */
	private void identifyClient() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		this.clientID = (Integer) this.in.readObject();
		System.out.println("KEYCHAIN : received client ID : " + this.clientID);
	}

}
