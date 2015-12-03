package p5;

import java.security.KeyPair;

import javax.crypto.SecretKey;

public class Main {

	final private static int KEY_LENGTH = 100;
	final private static String ALGORITMO = "RSA";
	final private static String MENSAJE = "VIVA PIT";
	
	public static void main(String[] args) {
		
		/* Hash del mensaje */
		String hash = SecurityUtils.hashMsg(MENSAJE);
		
		/* Criptografia de clave publica */
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(KEY_LENGTH, ALGORITMO);
		
		/* Criptografia de clave publica */
		SecretKey secretKey = SecurityUtils.generateSecretKey(KEY_LENGTH, ALGORITMO);
		
		/* Firma digital */
		
	}
}
