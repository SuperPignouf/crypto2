package connection;

import java.net.Socket;

public class Service extends Thread implements Runnable {

	private int ID;
	private Socket clientSocket;

	public Service(Socket accept) {
		this.ID = 0;
		this.clientSocket = accept;
	}

	@Override
	public void run() { //Recoit les messages de l'AS et traite les requetes des users
		// TODO Auto-generated method stub
		
	}

}
