package p5;

import java.security.KeyPair;
import java.security.Signature;

import javax.crypto.SecretKey;

/**
 * 
 * @author Alejandro Royo Amondarain (NIP: 560285)
 * 			Jaime Ruiz-Borau Vizárraga (NIP: 546751)
 *
 *	Esta clase contiene el codigo correspondiente a las pruebas y medida de
 *	tiempos de los diferentes metodos de hash, encriptacion y firma digital
 *	solicitados en el guion de la practica 5 de Seguridad Informatica.
 */
public class Main {

	final private static int[] KEY_LENGTHS = { 56, 512 };
	final private static String[] ALGORITMOS = { "SHA-256", "DES", "DSA" };
	final private static String MENSAJE = "VIVA PIT";

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
		System.out.println("Comienzo de creación de firma digital");
		System.out.println("Firmando...");
		startTime = System.nanoTime();
		Signature firma = SecurityUtils.createDigitalSignature(MENSAJE, keyPair, ALGORITMOS[2]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out
				.println("Tiempo de ejecución de creación de firma digital: " + duration + " milisegundos");
		
	}
}
