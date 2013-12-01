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

import dataBase.DbLink;


/**
 * Class to create a pair of keys (public and private) RSA.
 */
public class RsaKey {

	private Certificate myCert, adminCert;
	private PrivateKey privKey;
	//private KeyPair keyPair;

	/**
	 * Constructor: create a pair of keys (public and private) RSA.
	 * @throws IOException 
	 * @throws InvalidKeySpecException 
	 * @throws NoSuchAlgorithmException 
	 * @throws CertificateException 
	 * @throws SignatureException 
	 * @throws NoSuchProviderException 
	 * @throws InvalidKeyException 
	 */
	public RsaKey(DbLink dbLink) throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException{

		// Loading private key file

		String keyFile = "src/cakey.p8c";
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

		keyFile = "src/admincert.crt";
		inStream = new FileInputStream(keyFile);
		CertificateFactory cf = CertificateFactory.getInstance("X.509");
		this.adminCert = cf.generateCertificate(inStream);
		
		//loading AS cert
		
		this.myCert = dbLink.getCertificateByUserID(0);
		try {
			this.myCert.verify(this.adminCert.getPublicKey()); // On verifie que notre certificat a bien ete signe avec la cle publique presente sur le certificat de l'admin
			System.out.println(myCert);
		} catch (SignatureException e) {
			e.printStackTrace();
			System.out.println("You have the wrong key !");
		} catch (Exception e) {
			e.printStackTrace();
		}
	}

	public PublicKey getPubKey(){
		return this.myCert.getPublicKey();
	}

	public PrivateKey getPrivKey() {
		return this.privKey;
	}
	
	public Certificate getCert(){
		return this.myCert;
	}
}
