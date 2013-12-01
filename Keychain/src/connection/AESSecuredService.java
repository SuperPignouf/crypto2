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

public class AESSecuredService extends Thread implements Runnable {

	private int ID, clientID; // Id personnelle, ID du client
	private Socket clientSocket;
	private SecretKey ASAES; // La cle de session AES permettant de communiquer avec l'AS
	private KeychainWebService serviceServer;

	public AESSecuredService(Socket accept, SecretKey ASAESKey, KeychainWebService serviceServer) {
		this.ID = 1;
		this.clientSocket = accept;
		this.ASAES = ASAESKey;
		this.serviceServer = serviceServer;
	}
	
	/**
	 * //Recoit les messages de l'AS et traite les requetes des users
	 */
	@Override
	public void run() {
		try {
			this.clientID = identifyClient();
			if (this.clientID == 0){ // AS
				System.out.println("KEYCHAIN : AS identified");
				receiveUserIDAndSessionKey();
			}
			else if (this.clientID > 2){
				System.out.println("KEYCHAIN : user identified");
				runService(this.serviceServer.getIDAES(this.clientID));
			}
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (ClassNotFoundException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IllegalBlockSizeException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (BadPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchPaddingException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		
	}
	
	private void runService(IDAES idaes) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IOException, IllegalBlockSizeException{
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.ENCRYPT_MODE, idaes.getAES());
		ObjectOutputStream outO = new ObjectOutputStream(this.clientSocket.getOutputStream());
		
		String msg = "Bonjour client, je suis un Keychain";
		SealedObject encryptedMsg = new SealedObject (msg, cipher);
		outO.writeObject(encryptedMsg);
		outO.flush();
		
	}

	private void receiveUserIDAndSessionKey() throws IOException, ClassNotFoundException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException {
		Cipher cipher = Cipher.getInstance("AES");
		cipher.init(Cipher.DECRYPT_MODE, this.ASAES);
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		SealedObject encryptedUserID = (SealedObject) in.readObject();
		SealedObject encryptedAESKey = (SealedObject) in.readObject();
		SealedObject encryptedCryptoperiod = (SealedObject) in.readObject();
		byte[] AESKey = new byte[32];
		AESKey = (byte[]) encryptedAESKey.getObject(cipher);
		this.serviceServer.addIDAES((Integer) encryptedUserID.getObject(cipher), (Integer) encryptedCryptoperiod.getObject(cipher), new SecretKeySpec(AESKey, 0, 32, "AES")); // L'id de l'user et la cle associee sont stockees dans l'objet serviceServer
		
		System.out.println("KEYCHAIN : received client ID : " + (Integer) encryptedUserID.getObject(cipher));
		System.out.println("KEYCHAIN : received related session AES key : " + new SecretKeySpec(AESKey, 0, 32, "AES"));
		System.out.println("KEYCHAIN : received cryptoperiod of that key : " + (Integer) encryptedCryptoperiod.getObject(cipher) + "sec");
	}

	private int identifyClient() throws IOException, ClassNotFoundException, IllegalBlockSizeException, BadPaddingException, InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException {
		ObjectInputStream in = new ObjectInputStream(this.clientSocket.getInputStream());
		return (Integer) in.readObject();
	}

}
