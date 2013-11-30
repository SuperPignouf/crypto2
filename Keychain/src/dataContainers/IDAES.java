package dataContainers;

import javax.crypto.SecretKey;

public class IDAES { // Structure de donnees utilisee par le service pour retenir les cles de session AES et les id de clients associes

	private SecretKey AES;
	private int clientID;
	private int cryptoPeriod;
	
	public IDAES(SecretKey AES, int clientID, int cryptoPeriod){
		this.setAES(AES);
		this.setClientID(clientID);
		this.setCryptoPeriod(cryptoPeriod);
	}

	public boolean equals(IDAES a){
		return (this.AES.equals(a.AES) && this.clientID == a.clientID);
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

	public int getCryptoPeriod() {
		return cryptoPeriod;
	}

	public void setCryptoPeriod(int cryptoPeriod) {
		this.cryptoPeriod = cryptoPeriod;
	}
	
}
