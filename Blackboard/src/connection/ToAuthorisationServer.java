package connection;

import java.io.BufferedReader;
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

import javax.xml.bind.DatatypeConverter;

import crypto.RsaKey;

public class ToAuthorisationServer {
	
	private Socket client;
	private BufferedReader input;
	private PrintWriter output;
	private RsaKey rsaKey;
	private PublicKey asPubKey;

	public 	ToAuthorisationServer(RsaKey rsaKey) throws NoSuchAlgorithmException, InvalidKeySpecException{
		
		this.rsaKey = rsaKey;
		initConnection();
		sendPubKey();
		//receiveASPubKey();
		closeConnection();

		//printKeys();
	}
	
	private void printKeys() {
		System.out.println("Server PK:" + DatatypeConverter.printHexBinary(asPubKey.getEncoded()));
		System.out.println("My PK:" + DatatypeConverter.printHexBinary(rsaKey.getKeyPair().getPublic().getEncoded()));
		
	}

	private void closeConnection() {
		try {
			output.close();
			input.close();
			client.close();
		} 
		catch (IOException e) {
			System.out.println(e);
		}
		
	}

	private void receiveASPubKey() throws NoSuchAlgorithmException, InvalidKeySpecException {
		//System.out.println("CLIENT: Attente de reception de cle RSA publique.");
		try{
			byte[] lenb = new byte[4];
			this.client.getInputStream().read(lenb,0,4);
            ByteBuffer buffer = ByteBuffer.wrap(lenb);
            int len = buffer.getInt();
            //System.out.println(len);
            byte[] servPubKeyBytes = new byte[len];
            this.client.getInputStream().read(servPubKeyBytes);
            //System.out.println(DatatypeConverter.printHexBinary(servPubKeyBytes));
            X509EncodedKeySpec ks = new X509EncodedKeySpec(servPubKeyBytes);
            KeyFactory kf = KeyFactory.getInstance("RSA");
            this.asPubKey = kf.generatePublic(ks);
            //System.out.println(DatatypeConverter.printHexBinary(asPubKey.getEncoded()));
		} catch (IOException e){
			System.out.println("Read failed");
			System.exit(1);
		}
		
	}

	private void sendPubKey() {
		PublicKey servicePubKey = this.rsaKey.getKeyPair().getPublic();
		//System.out.println(DatatypeConverter.printHexBinary(servicePubKey.getEncoded()));
		output.print(servicePubKey.getEncoded());
		output.flush();
		
	}

	private void initConnection(){
		this.client = null;
		try {
			client = new Socket("localhost", 2442);
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.input = null;
		try {
			input = new BufferedReader(new InputStreamReader(client.getInputStream()));
		}
		catch (IOException e) {
			System.out.println(e);
		}

		this.output = null; //Ouverture d'un canal de sortie
		try {
			output = new PrintWriter(client.getOutputStream(), true);
		}
		catch (IOException e) {
			System.out.println(e);
		}
	}

}
