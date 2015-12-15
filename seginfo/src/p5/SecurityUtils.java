package p5;

import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

public class SecurityUtils {

	public static String hashMsg(String msg, String algoritmo){
		MessageDigest md = null;
		try {
			md = MessageDigest.getInstance(algoritmo);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
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
	
	public static SecretKey generateSecretKey(int keyLength, String algoritmo){
		SecretKey s = null;
		try {
			KeyGenerator g = KeyGenerator.getInstance(algoritmo);
			g.init(keyLength);
			s = g.generateKey();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		}
		return s;
	}
	
	public static KeyPair generatePrivatePublicKey(int keyLength, String algoritmo){
		KeyPair p = null;
		try {
			KeyPairGenerator g = KeyPairGenerator.getInstance(algoritmo);
			g.initialize(keyLength);
			p = g.generateKeyPair();
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		}
		return p;
	}
	
	public static Signature createDigitalSignature(String message, PublicKey pub, PrivateKey priv, String alg1, String alg2) {
		
		/* Hash del mensaje */
		String msg = hashMsg(message, alg1);
		Signature dsa = null;
		/* Firma con mi clave publica */
		try {
			dsa = Signature.getInstance(alg2);
			/* Initializing the object with a private key */
			dsa.initSign(priv);

			/* Update and sign the data */
			dsa.update(msg.getBytes());
			byte[] sig = dsa.sign();
			
			/* Initializing the object with the public key */
			dsa.initVerify(pub);

			/* Update and verify the data */
			dsa.update(msg.getBytes());
			boolean verifies = dsa.verify(sig);
			System.out.println("signature verifies: " + verifies);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (SignatureException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (InvalidKeyException e) {
			e.printStackTrace();
			System.exit(0);
		}
		
		/* Devuelve la firma */
		return dsa;
	}
}
