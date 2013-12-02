package dataBase;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.SQLException;

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
			String OS = System.getProperty("os.name").toLowerCase();
			if(OS.contains("mac")) {
				this.con = DriverManager.getConnection("jdbc:mysql://localhost:8889/keychainDB","root", "root");
			} else { //linux or windows
				this.con = DriverManager.getConnection("jdbc:mysql://localhost/keychainDB","root", "");
			}

		} catch (SQLException e) {
			System.out.println("Connection Failed! Check output console");
			e.printStackTrace();
			return;
		}

		if (con != null) {
			System.out.println("You made it, take control of your database now!");
		} else {
			System.out.println("Failed to make connection!");
		}
	}
	
	
}
