package crypto;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;


/**
 * Class to create a pair of keys (public and private) RSA.
 */
public class RsaKey {

	private Certificate myCert, adminCert;
	private PrivateKey privKey;

	/**
	 * Constructor: create a pair of keys (public and private) RSA.
	 * @throws IOException 
	 * @throws NoSuchAlgorithmException 
	 * @throws InvalidKeySpecException 
	 * @throws CertificateException 
	 */
	public RsaKey() throws IOException, NoSuchAlgorithmException, InvalidKeySpecException, CertificateException{

		//String keyFile = "src/BBkey.p8c"; //TODO
		String keyFile = "BBkey.p8c";
		InputStream inStream = new FileInputStream(keyFile);
		byte[] encKey = new byte[inStream.available()];
		inStream.read(encKey);
		inStream.close();

		// Read the private key from file

		System.out.println("RSA PrivateKeyInfo: " + encKey.length + " bytes\n");
		PKCS8EncodedKeySpec privKeySpec = new PKCS8EncodedKeySpec(encKey);
		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
		System.out.println("KeyFactory Object Info:");
		System.out.println("Algorithm = "+ keyFactory.getAlgorithm());
		System.out.println("Provider = "+ keyFactory.getProvider());
		this.privKey = (RSAPrivateKey) keyFactory.generatePrivate(privKeySpec);
		System.out.println("Loaded " + this.privKey.getAlgorithm() + " " + this.privKey.getFormat() + " private key.");

		//loading admin certificate

		//keyFile = "src/admincert.crt"; //TODO
		keyFile = "admincert.crt";
		inStream = new FileInputStream(keyFile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		this.adminCert = cf.generateCertificate(inStream);

		//loading my certificate

		//keyFile = "src/BBcert.crt"; //TODO
		keyFile = "BBcert.crt";
		inStream = new FileInputStream(keyFile);
		cf = CertificateFactory.getInstance("X.509");
		this.myCert = cf.generateCertificate(inStream);

	}

	public PrivateKey getPrivKey(){
		return this.privKey;
	}
	
	public PublicKey getPubKey(){
		return this.myCert.getPublicKey();
	}

	public boolean verify(Certificate cert){
		try {
			cert.verify(this.adminCert.getPublicKey());
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			return false;
		} catch (CertificateException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return false;
		} catch (NoSuchProviderException e) {
			e.printStackTrace();
			return false;
		} catch (SignatureException e) {	
			e.printStackTrace();
			return false;
		}
		return true;
	}
	
}
