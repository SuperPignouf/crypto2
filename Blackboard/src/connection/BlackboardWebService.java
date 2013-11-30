package connection;

import java.io.IOException;
import java.net.ServerSocket;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.List;

import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;

import dataContainers.IDAES;
import crypto.RsaKey;

/**
 * The "main" class of the blackboard. It starts by connecting to the Authorisation Server to receive a session key (AS-WS AES key), and then
 * accepts connections in a symmetric encryption style.
 */
public class BlackboardWebService {
	
	private SecretKey ASWSAESKey; // The AS-WS AES session key.
	private ServerSocket myService;
	private List<IDAES> IDAESList; // List of keys allowing to communicate with Clients and ID's of corresponding Clients.

	public BlackboardWebService(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		ToAuthorisationServerUsingRSA TAS = new ToAuthorisationServerUsingRSA(rsaKey);
		this.ASWSAESKey = TAS.getASWSAESKey(); // Get the AS-WS AES session key from the AS.
		initSocketConnection();
		acceptConnections(); // On est pret a recevoir des requetes
	}
	
	/**
	 * Accepts connections with Clients using AES.
	 */
	private void acceptConnections() {
		while(true){			
			try {
				//Service BB = new Service(this.myService.accept());
				//BB.run();
				new AESSecuredService(this.myService.accept(), this.ASWSAESKey, this).run();
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
	
	public void addIDAES(int ID, int cryptoPeriod, SecretKey AESKey){
		this.IDAESList.add(new IDAES(AESKey, cryptoPeriod, ID));
	}
	
	public void removeIDAES(int ID, SecretKey AESKey){
		IDAES idaes = new IDAES(AESKey, 0, ID) ;
		for(IDAES i : this.IDAESList){
			if(i.equals(idaes)) this.IDAESList.remove(i);
		}
	}

	public void setASWSAES(SecretKey ASWSAESKey) {
		this.ASWSAESKey = ASWSAESKey;
	}
	
	public IDAES getIDAES(int id){
		for(IDAES i : this.IDAESList){
			if(i.getClientID() == id)
				return i;
		}
		return null;	
	}

}
