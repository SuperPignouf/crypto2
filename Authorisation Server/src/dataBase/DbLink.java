package dataBase;

import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.spec.X509EncodedKeySpec;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.Statement;

public class DbLink {

	private Connection con;
	
	public DbLink(){

		try {
			Class.forName("com.mysql.jdbc.Driver");
		} catch (ClassNotFoundException e) {
			System.out.println("Where is your MySQL JDBC Driver?");
			e.printStackTrace();
			return;
		}

		System.out.println("MySQL JDBC Driver Registered!");

		try {
			this.con = DriverManager.getConnection("jdbc:mysql://localhost/crypto2","root", "");

		} catch (SQLException e) {
			System.out.println("Connection Failed! Check output console");
			e.printStackTrace();
			return;
		}

		if (con != null) {
			System.out.println("You made it, take control your database now!");
		} else {
			System.out.println("Failed to make connection!");
		}
	}


	public Certificate getCertificateByUserID(int ID) throws NoSuchAlgorithmException, CertificateException{

		Certificate result = null;
		PreparedStatement ps = null;
		ResultSet rs = null;
		try {
			ps = this.con.prepareStatement("SELECT * FROM certificates where ID = ?");
			ps.setInt (1, ID);
			rs = ps.executeQuery();

			if(rs.next()){
				String str = rs.getString("Certificate");
				System.out.println(str);
				InputStream is = new ByteArrayInputStream(str.getBytes());
				CertificateFactory cf = CertificateFactory.getInstance("X.509");
				result = cf.generateCertificate(is);
				
				System.out.println("LOOK HERE : " + result.getEncoded().length);


			
			}
			System.out.println("ICI : " + rs.getString("Certificate"));

			//System.out.println("cctvmb ?");


			System.out.println(result);

		} catch (SQLException e) {
			System.out.println(e);
		}
		return result; 
	}

}
