package p5;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecurityUtils {

	public static String hashMsg(String msg){
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance("SHA-256");
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
		}
		md.update(msg.getBytes());

		byte byteData[] = md.digest();

		// Convertir los bytes a hexadecimal
		StringBuffer sb = new StringBuffer();
		for (int i = 0; i < byteData.length; i++) {
			sb.append(Integer.toString((byteData[i] & 0xff) + 0x100, 16).substring(1));
		}

		return sb.toString();
	}
	
	public static SecretKey generateSecretKey(int keyLength){
		SecretKey s = null;
		try {
			KeyGenerator g = KeyGenerator.getInstance("RSA");
			s = g.generateKey();
		} catch (NoSuchAlgorithmException e) {
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