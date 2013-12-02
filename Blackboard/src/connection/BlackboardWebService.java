

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

import dataContainers.IDAES;
import crypto.RsaKey;

/**
 * The "main" class of the blackboard. It starts by connecting to the Authorisation Server to receive a session key (AS-BlackBoard AES key), and then
 * accepts connections in a symmetric encryption style.
 */
public class BlackboardWebService {
	
	private int ID = 1, userID = -1;
	private SecretKey ASBlackboardAESKey;
	private ServerSocket myService;
	private Socket clientSocket = null;
	private Thread t;
	private ArrayList<IDAES> IDAESList = new ArrayList<IDAES>(); // List of keys allowing to communicate with Clients and ID's of corresponding Clients.

	public BlackboardWebService(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		BlackboardToAuthorisationServerUsingRSA TAS = new BlackboardToAuthorisationServerUsingRSA(this, this.ID, rsaKey);
		this.ASBlackboardAESKey = TAS.getASBlackboardAESKey();
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
				System.out.println("\nBLACKBOARD: Someone wants to connect.");
				t = new Thread(new BlackboardAESSecuredService(this, this.clientSocket, this.ASBlackboardAESKey));
				t.start();
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}
	
	/**
	 * Initializes the socket (port 4224).
	 * @throws IOException
	 */
	private void initSocketConnection() throws IOException {
		this.myService = new ServerSocket(4224);
		
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
	 * @param userID - the user's ID.
	 */
	public void setUserID(int userID) {
		this.userID = userID;
	}
	
	/**
	 * Add a client's ID, the secret key (AES) shared with this client, and the cryptoperiod.
	 * @param ID - the client's ID.
	 * @param cryptoPeriod - the cryptoperiod.
	 * @param AESKey - the secret key (AES) shared with the client.
	 */
	public void addIDAES(int ID, int cryptoPeriod, SecretKey AESKey){
		this.IDAESList.add(new IDAES(AESKey, ID, cryptoPeriod));
	}
	
	/**
	 * Remove the client's ID, and the secret key (AES) shared with this client.
	 * @param ID - the client's ID.
	 * @param AESKey - the secret key (AES) shared with the client.
	 */
	public void removeIDAES(int ID, SecretKey AESKey){
		IDAES idaes = new IDAES(AESKey, 0, ID) ;
		for(IDAES i : this.IDAESList){
			if(i.equals(idaes)) this.IDAESList.remove(i);
		}
	}

	/**
	 * Sets the key AES which is used for the communication between this web service and the AS.
	 * @param ASBlackboardAESKey - the key
	 */
	public void setASBlackboardAES(SecretKey ASBlackboardAESKey) {
		this.ASBlackboardAESKey = ASBlackboardAESKey;
	}
	
	public IDAES getIDAES(int id){
		for(IDAES i : this.IDAESList){
			if(i.getClientID() == id)
				return i;
		}
		return null;	
	}

}

