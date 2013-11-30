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

     private Certificate cert;
     private PrivateKey privKey;

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
	public RsaKey() throws IOException, InvalidKeySpecException, NoSuchAlgorithmException, CertificateException, InvalidKeyException, NoSuchProviderException, SignatureException{

		//		File file = new File("src\\chicken.der");
		//		FileInputStream fis = new FileInputStream(file);
		//		DataInputStream dis = new DataInputStream(fis);
		//		byte[] keyBytes = new byte[(int)file.length()];
		//	    dis.readFully(keyBytes);
		//	    dis.close();
		//		
		//	    PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
		//	    KeyFactory kf = KeyFactory.getInstance("RSA");
		//	    PrivateKey pk = kf.generatePrivate(spec);
		//
		//		System.out.println(spec);
		//		fis.close();

/*		KeyPairGenerator keyPairGenerator = null;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance("RSA"); //RSA
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		keyPairGenerator.initialize(1024); //1024 bits
		this.keyPair = keyPairGenerator.genKeyPair();*/

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
        
        //Certificate MF !
        
        keyFile = "src/cacert.pem";
        inStream = new FileInputStream(keyFile);
        CertificateFactory cf = CertificateFactory.getInstance("X.509");
        this.cert = cf.generateCertificate(inStream);
        try {
        	this.cert.verify(cert.getPublicKey());
			System.out.println(cert);
        } catch (SignatureException e) {
			e.printStackTrace();
			System.out.println("You have the wrong key !");
		} catch (Exception e) {
			e.printStackTrace();
		}
        
        
	}

	public PublicKey getPubKey(){
		return this.cert.getPublicKey();
	}

	public PrivateKey getPrivKey() {
		return this.privKey;
	}

}


