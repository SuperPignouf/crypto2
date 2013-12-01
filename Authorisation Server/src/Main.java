import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.cert.CertificateException;
import java.security.spec.InvalidKeySpecException;

import connection.AuthorisationServer;
import crypto.RsaKey;
import dataBase.DbLink;

/**
 * Main class: Creates the Authorisation Server.
 */
public class Main {

	/**
	 * Main: create the Authorization Server.
	 * @param args arguments for the main.
	 * @throws NoSuchAlgorithmException
	 * @throws IOException
	 */
	public static void main(String[] args){
		
		DbLink dbLink = new DbLink();
		
		try {
			@SuppressWarnings("unused")
			AuthorisationServer AS = new AuthorisationServer(new RsaKey(dbLink));
			//AuthorisationServer AS = new AuthorisationServer(new RsaKey());
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (IOException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (CertificateException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		} catch (SignatureException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
	}


}
