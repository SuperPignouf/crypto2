import java.util.Scanner;

import connection.ToAuthorisationServer;


public class Main {
	public static void main(String[] args){
		System.out.println("Hello, which service would you access to ? (keychain: k , blackboard: b )");
		Scanner sc = new Scanner(System.in);
		String response = sc.next();
		
		ToAuthorisationServer TAS = new ToAuthorisationServer();
	}
}
