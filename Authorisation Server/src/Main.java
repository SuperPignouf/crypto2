import java.security.NoSuchAlgorithmException;

import connection.ConnectionReceiver;
import crypto.RsaKey;

public class Main {
	public static void main(String[] args) throws NoSuchAlgorithmException{
		ConnectionReceiver CR = new ConnectionReceiver(new RsaKey());
	}
}
