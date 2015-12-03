package p5;

import java.security.KeyPair;

import javax.crypto.SecretKey;

public class Main {

	final private static int[] KEY_LENGTHS = { 56, 512 };
	final private static String[] ALGORITMOS = { "SHA-256", "DES", "DSA" };
	final private static String MENSAJE = "VIVA PIT";

	@SuppressWarnings("unused")
	public static void main(String[] args) {

		/* Hash del mensaje */
		System.out.println("Comienzo del hasheo");
		System.out.println("Hasheando...");
		long startTime = System.nanoTime();
		String hash = SecurityUtils.hashMsg(MENSAJE, ALGORITMOS[0]);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de hasheo: " + duration + " milisegundos");

		/* Criptografia de clave secreta */
		System.out.println("Comienzo de generación de clave secreta");
		System.out.println("Generando...");
		startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(KEY_LENGTHS[0], ALGORITMOS[1]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");

		/* Criptografia de clave publica */
		System.out.println("Comienzo de generación de clave privada y clave pública");
		System.out.println("Generando...");
		startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(KEY_LENGTHS[1], ALGORITMOS[2]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out
				.println("Tiempo de ejecución de generación de clave publica y privada: " + duration + " milisegundos");

		/* Firma digital */

	}
}
