package p5;

import java.security.KeyPair;

import javax.crypto.SecretKey;

public class Main {

	final private static int KEY_LENGTH = 100;
	final private static String[] ALGORITMOS = {"RSA", "SHA-256"};
	final private static String MENSAJE = "VIVA PIT";

	@SuppressWarnings("unused")
	public static void main(String[] args) {

		/* Hash del mensaje */
		long startTime = System.nanoTime();
		String hash = SecurityUtils.hashMsg(MENSAJE, ALGORITMOS[1]);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de hasheo: " + duration + " milisegundos");

		/* Criptografia de clave secreta */
		startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(KEY_LENGTH, ALGORITMOS[0]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");

		/* Criptografia de clave publica */
		startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(KEY_LENGTH, ALGORITMOS[0]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");
		
		/* Firma digital */

	}
}
