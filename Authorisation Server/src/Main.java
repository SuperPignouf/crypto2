
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
			new AuthorisationServer(new RsaKey(dbLink));
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		} catch (IOException e) {
			e.printStackTrace();
		} catch (InvalidKeyException e) {
			e.printStackTrace();
		} catch (CertificateException e) {
			e.printStackTrace();
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
		} catch (SignatureException e) {
			e.printStackTrace();
		}
		catch (InvalidKeySpecException e) {
			e.printStackTrace();
		}
	}


}
