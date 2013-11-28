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

public class ServiceServer {
	
	private SecretKey ASAESKey; // La cle permettant de communiquer avec l'AS
	private ServerSocket myService;
	private List<IDAES> IDAES; // Les cles permettant de communiquer avec les clients et les ID des clients associes

	public ServiceServer(RsaKey rsaKey) throws InvalidKeyException, NoSuchAlgorithmException, NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, IOException, ClassNotFoundException {
		ToAuthorisationServer TAS = new ToAuthorisationServer(rsaKey); // Authentification avec l'AS
		this.ASAESKey = TAS.getASAESKey(); // Reception de la cle de session AES permettant de communiquer avec l'AS
		initSocketConnection(); // Initialisation du socket serveur
		acceptConnections(); // On est pret a recevoir des requetes
	}

	private void acceptConnections() {
		while(true){			
			try {
				Service BB = new Service(this.myService.accept());
				BB.run();
			}
			catch (IOException e) {
				System.out.println(e);
			}					    
		}
	}

	private void initSocketConnection() throws IOException {
		this.myService = new ServerSocket(4224);
		
	}

	
}
