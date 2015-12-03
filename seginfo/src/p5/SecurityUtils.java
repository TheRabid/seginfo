package p5;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecurityUtils {

	public static String hashMsg(String msg){
		
	}
	
	public static SecretKey generateSecretKey(int keyLength){
		SecretKey s = null;
		try {
			KeyGenerator g = KeyGenerator.getInstance("RSA");
			s = g.generateKey();
		} catch (NoSuchAlgorithmException e) {
			// TODO Auto-generated catch block
			e.printStackTrace();
		}
		return s;
	}
	
	public static KeyPair generatePrivatePublicKey(int keyLength){
		KeyPair p = null;
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
			g.initialize(keyLength);
			p = g.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		return p;
	}
}
