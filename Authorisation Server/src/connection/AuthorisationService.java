package connection;

import java.io.BufferedReader;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.nio.ByteBuffer;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import crypto.RsaKey;

public class AuthorisationService implements Runnable {

	private Socket clientSocket;
	private RsaKey rsaKey;
	private BufferedReader input;
	private PrintWriter output;
	private PublicKey clientPubKey;
	private byte[] buffer;
	
	public AuthorisationService(Socket clientSocket, RsaKey rsaKey) {
		this.clientSocket = clientSocket;
		this.rsaKey = rsaKey;
		this.buffer = new byte[2000];
	}

	@Override
	public void run() {
		
		initConnection();
		sendPubKey();
		try {
			receiveClientPubKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		closeConnection();
		
		

		
	}

	private void closeConnection() {
		
		try {
	        output.close();
	        input.close();
	        this.clientSocket.close();
	        
	     } 
	     catch (IOException e) {
	        System.out.println(e);
	     }
		
	}

	private void receiveClientPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		try{
			byte[] lenb = new byte[4];
			this.clientSocket.getInputStream().read(lenb,0,4);
            ByteBuffer buffer = ByteBuffer.wrap(lenb);
            int len = buffer.getInt();
            //System.out.println(len);
            //byte[] clientPubKeyBytes = new byte[len];
            //this.clientSocket.getInputStream().read(clientPubKeyBytes);
            this.clientSocket.getInputStream().read(this.buffer);
            //System.out.println(DatatypeConverter.printHexBinary(servPubKeyBytes));
            //X509EncodedKeySpec ks = new X509EncodedKeySpec(clientPubKeyBytes);
            X509EncodedKeySpec ks = new X509EncodedKeySpec(this.buffer);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.clientPubKey = kf.generatePublic(ks);
            //System.out.println(DatatypeConverter.printHexBinary(asPubKey.getEncoded()));
		} catch (IOException e){
			System.out.println("Read failed");
			System.exit(1);
		}
		
		
	}

	private void sendPubKey() {
		PublicKey ASPubKey = this.rsaKey.getKeyPair().getPublic();
		ByteBuffer buffer = ByteBuffer.allocate(4);
		buffer.putInt(ASPubKey.getEncoded().length);
		output.print(buffer.array());
		//System.out.println(DatatypeConverter.printHexBinary(servicePubKey.getEncoded()));
		output.print(ASPubKey.getEncoded());
		output.flush();
		
	}

	private void initConnection() {
		this.input = null; //Ouverture d'un canal d'entree
		try {
			input = new BufferedReader(new InputStreamReader(this.clientSocket.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.output = null; //Ouverture d'un canal de sortie
		try {
			output = new PrintWriter(this.clientSocket.getOutputStream(), true);
		}
		catch (IOException e) {
			System.out.println(e);
		}
		
	}

}
