package dataContainers;

import javax.crypto.SecretKey;

public class IDAES { // Structure de donnees utilisee par le service pour retenir les cles de session AES et les id de clients associes

	private SecretKey AES;
	private int clientID;
	
	public IDAES(SecretKey AES, int clientID){
		this.setAES(AES);
		this.setClientID(clientID);
	}

	public SecretKey getAES() {
		return AES;
	}

	public void setAES(SecretKey aES) {
		AES = aES;
	}

	public int getClientID() {
		return clientID;
	}

	public void setClientID(int clientID) {
		this.clientID = clientID;
	}
	
}
