package connection;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.ArrayList;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import dataBase.DbLink;
import dataContainers.IDAES;
import crypto.RsaKey;

/**
 * The "main" class of the blackboard. It starts by connecting to the Authorisation Server to receive a session key (AS-BB AES key), and then
 * accepts connections in a symmetric encryption style.
 */
public class KeychainWebService {
	
	private int ID = 2, userID = -1;
	private SecretKey ASKeychainAESKey;
	private ServerSocket myService;
	private Socket clientSocket = null;
	private Thread t;
	private ArrayList<IDAES> IDAESList = new ArrayList<IDAES>(); // List of keys allowing to communicate with Clients and ID's of corresponding Clients.
	DbLink dbLink=null;

	public KeychainWebService(RsaKey rsaKey, DbLink dblink) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		KeychainToAuthorisationServerUsingRSA TAS = new KeychainToAuthorisationServerUsingRSA(this, this.ID, rsaKey);
		this.ASKeychainAESKey = TAS.getASKeychainAESKey();
		this.dbLink=dblink;
		initSocketConnection();
		acceptConnections();
	}
	
	/**
	 * Accepts connections with Clients using AES.
	 */
	private void acceptConnections() {
		while(true){			
			try {
				this.clientSocket = this.myService.accept();
				System.out.println("\nKEYCHAIN: Someone wants to connect.");
				t = new Thread(new KeychainAESSecuredService(this, this.clientSocket, this.ASKeychainAESKey, this.dbLink));
				t.start();
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}
	
	/**
	 * Initializes the socket (port 4225).
	 * @throws IOException
	 */
	private void initSocketConnection() throws IOException {
		this.myService = new ServerSocket(4225);
		
	}
	
	/**
	 * Gets the user's ID.
	 * @return the user's ID.
	 */
	public int getUserID() {
		return this.userID;
	}
	
	/**
	 * Sets the user's ID.
	 * @param userID
	 */
	public void setUserID(int userID) {
		this.userID = userID;
	}
	
	public void addIDAES(int ID, int cryptoPeriod, SecretKey AESKey){
		this.IDAESList.add(new IDAES(AESKey, ID, cryptoPeriod));
	}
	
	public void removeIDAES(int ID, SecretKey AESKey){
		IDAES idaes = new IDAES(AESKey, 0, ID) ;
		for(IDAES i : this.IDAESList){
			if(i.equals(idaes)) this.IDAESList.remove(i);
		}
	}

	public void setASKeychainAES(SecretKey ASKeychainAESKey) {
		this.ASKeychainAESKey = ASKeychainAESKey;
	}
	
	public IDAES getIDAES(int id){
		for(IDAES i : this.IDAESList){
			if(i.getClientID() == id)
				return i;
		}
		return null;	
	}

}

