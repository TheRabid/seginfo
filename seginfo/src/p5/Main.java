package p5;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.math.RoundingMode;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.text.DecimalFormat;
import java.util.Calendar;
import java.util.GregorianCalendar;
import java.util.Scanner;
import java.util.UUID;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.x509.X509V3CertificateGenerator;

/**
 * 
 * @author Alejandro Royo Amondarain (NIP: 560285)
 * 		   Jaime Ruiz-Borau Vizarraga (NIP: 546751)
 *
 *         Esta clase contiene el codigo correspondiente a las pruebas y medida
 *         de tiempos de los diferentes metodos de hash, encriptacion y firma
 *         digital solicitados en el guion de la practica 5 de Seguridad
 *         Informatica.
 *         
 *         Justificaciones:
 *         
 *         	-HASH:
 *         		Para el hasheo de un mensaje, se ha optado por el empleo de un
 *         		algoritmo SHA-256 ya que produce una "huella digital" de 256 bits.
 * 
 * 				Como habitualmente se emplean los algoritmos MD5 y SHA-1, que son de
 * 				128 y 160 bits respectivamente, esta implementación proporciona una
 * 				mayor seguridad.
 * 
 *         	-FIRMA DIGITAL:
 *         		Para la firma digital se ha optado por el algoritmo de hash
 *         		SHA-256 con encriptado de RSA. La eleccion de RSA se debe a
 *         		que es el mas utilizado actualmente.
 *         
 *         	-CLAVE PUBLICA/PRIVADA:
 * 				Para la generación de una clave privada y publica se ha elegido
 * 				el algoritmo RSA, con un tamano de clave de 1024 bits. Se ha
 * 				utilizado el modo de encriptado "ECB" (Electronic Code Book)
 * 				y el padding PKCS1.
 * 
 * 				Los motivos de esta decision son que el algoritmo RSA es mas
 * 				rapido computacionalmente que otros algoritmos como el DSA.
 *         		
 *          -CLAVE SECRETA:
 *          	Para la generación de una clave secreta se ha elegido el 
 *          	algoritmo AES, con un tamano de clave de 128 bits, ya que es 
 *          	el estandar que sustituyo al algorito DES en Estados Unidos y
 *          	ha demostrado ser mas seguro y rapido que el propio DES o su
 *          	variante TDES.
 */

@SuppressWarnings("deprecation")
public class Main {

	final private static int[] KEY_LENGTHS = { 128, 512, 1024, 2048 };
	final private static String[] ALGORITMOS = { "SHA-256", "AES", "RSA", "SHA256withRSA" };
	final private static String[] BLOCKSPADDING = { "/CBC/PKCS5Padding", "/ECB/PKCS1Padding" };
	final private static String MENSAJE = "Mensaje de prueba";
	final private static String PASSWORD = "password";
	final private static boolean debug = false;
	final private static int VECES = 50;
	final private static String DIR_NAME = "Minizaguan";
	private static PublicKey pub = null;

	@SuppressWarnings("unused")
	public static void main(String[] args) throws Exception {

		DecimalFormat df = new DecimalFormat("#.##");
		df.setRoundingMode(RoundingMode.CEILING);

		/* Hash */
		System.out.println("Calculando tiempos de ejecucion de generacion de hash...");
		double mediaTiempoHash = 0;
		for (int i = 0; i < VECES; i++) {
			double durationHash = hashTest(MENSAJE, ALGORITMOS[0]);
			mediaTiempoHash = mediaTiempoHash + durationHash;
		}
		mediaTiempoHash = mediaTiempoHash / ((double) VECES);
		System.out.println("Tiempo medio de " + VECES + " calculos de hash:\t\t\t\t\t" + df.format(mediaTiempoHash)
				+ " milisegundos");
		System.out.println();

		/* Almacen de claves */
		/**
		 * Creacion del almacen de claves. Dado que estamos usando la Java
		 * Cryptography Extension, el almacen de claves sera de tipo JCEKS
		 */

		KeyStore ks = null;
		ks = KeyStore.getInstance("JCEKS");
		ks.load(null, PASSWORD.toCharArray());
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD.toCharArray());

		/* Generar clave secreta */
		System.out.println("Calculando tiempos de ejecucion de generacion de clave secreta...");
		double mediaTiempoSecretKey = 0;
		for (int i = 0; i < VECES; i++) {
			double durationSecretKey = secretKeyTest(KEY_LENGTHS[0], ALGORITMOS[1], ks, false);
			mediaTiempoSecretKey = mediaTiempoSecretKey + durationSecretKey;
		}
		mediaTiempoSecretKey = mediaTiempoSecretKey / ((double) VECES);
		System.out.println("Tiempo medio de " + VECES + " calculos de clave secreta:\t\t\t\t"
				+ df.format(mediaTiempoSecretKey) + " milisegundos");
		System.out.println();

		/* Almacenar clave secreta */
		secretKeyTest(KEY_LENGTHS[0], ALGORITMOS[1], ks, true);
		KeyStore.SecretKeyEntry secrEntry = (KeyStore.SecretKeyEntry) ks.getEntry("secretkey", protParam);

		/* Generar clave publica/privada */
		for (int k = 1; k < 4; k++) {
			System.out.println(
					"Calculando tiempos de generacion de claves publica/privada con tamano " + KEY_LENGTHS[k] + "...");
			double mediaTiempoPriPub = 0;
			for (int i = 0; i < VECES; i++) {
				double durationPriPub = privatePublicKeyTest(KEY_LENGTHS[k], ALGORITMOS[2], ALGORITMOS[3], ks, false);
				mediaTiempoPriPub = mediaTiempoPriPub + durationPriPub;
			}
			mediaTiempoSecretKey = mediaTiempoSecretKey / ((double) VECES);
			System.out.println("Tiempo medio de " + VECES + " calculos de clave publica/privada con tamano "
					+ KEY_LENGTHS[k] + ":\t" + df.format(mediaTiempoPriPub) + " milisegundos");
			System.out.println();
		}

		/* Almacenar clave privada (la publica es un atributo de la clase) */
		privatePublicKeyTest(KEY_LENGTHS[2], ALGORITMOS[2], ALGORITMOS[3], ks, true);
		PrivateKey pri = (PrivateKey) ks.getKey("privatekey", PASSWORD.toCharArray());

		/* Firma digital */
		System.out.println("Calculando tiempos de generacion de firma digital...");
		double mediaTiempoSign = 0;
		for (int i = 0; i < VECES; i++) {
			double durationSign = digitalSignatureTest(pub, pri);
			mediaTiempoSign = mediaTiempoSign + durationSign;
		}
		mediaTiempoSign = mediaTiempoSign / ((double) VECES);
		System.out.println("Tiempo medio de " + VECES + " calculos de firma:\t\t\t\t\t" + df.format(mediaTiempoSign)
				+ " milisegundos");
		System.out.println();

		/* Genera un vector de bytes para utilizar en caso de clave secreta */
		String initVector = "RandomInitVector"; // 16 bytes IV
		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF8"));

		/* Lee los ficheros y los cifra */
		File dir = new File(DIR_NAME);
		if (dir.exists()) {
			File[] ficheros = dir.listFiles();
			double tiempoMedioCifrado = 0.0;
			double tiempoMedioDescifrado = 0.0;

			System.out.println("Calculando tiempos de encriptacion de documentos con clave secreta...");
			/* Cifrado y descifrado con clave secreta */
			for (int i = 0; i < ficheros.length; i++) {

				/* Genera la clave secreta */
				SecretKey secKey = SecurityUtils.generateSecretKey(KEY_LENGTHS[0], ALGORITMOS[1]);

				/* Lee un fichero */
				String mensaje = leerFichero(ficheros[i]);

				/* Cifra el contenido de un fichero */
				long startTime = System.nanoTime();
				byte[] mensajeEnc = encrypt(secKey, iv, mensaje, ALGORITMOS[1], BLOCKSPADDING[0]);
				long endTime = System.nanoTime();
				double tiempoCifrado = (endTime - startTime) / (1000000.0);

				/* Descifra el contenido de un fichero cifrado */
				startTime = System.nanoTime();
				String mensajeFinal = decrypt(secKey, iv, mensajeEnc, ALGORITMOS[1], BLOCKSPADDING[0]);
				endTime = System.nanoTime();
				double tiempoDescifrado = (endTime - startTime) / (1000000.0);

				tiempoMedioCifrado += tiempoCifrado;
				tiempoMedioDescifrado += tiempoDescifrado;

			}
			tiempoMedioCifrado = tiempoMedioCifrado / ficheros.length;
			tiempoMedioDescifrado = tiempoMedioDescifrado / ficheros.length;

			System.out.println("Tiempo medio cifrado con clave secreta de " + ficheros.length + " documentos:\t\t"
					+ df.format(tiempoMedioDescifrado) + " ms.");
			System.out.println("Tiempo medio descifrado con clave secreta de " + ficheros.length + " documentos:\t\t"
					+ df.format(tiempoMedioDescifrado) + " ms.");
			System.out.println();
		}
		
		/* Cifrado y descifrado con clave secreta */
		double tiempoMedioCifrado = 0.0;
		double tiempoMedioDescifrado = 0.0;
		int veces = 100;
		System.out
				.println("Calculando tiempos de encriptacion de mensajes aleatorios con clave secreta...");
		for (int i = 0; i < veces; i++) {

			SecretKey secKey = SecurityUtils.generateSecretKey(KEY_LENGTHS[0], ALGORITMOS[1]);
			
			/* Genera un mensaje random */
			String mensaje = generateRandomString(KEY_LENGTHS[2]);

			/*
			 * Cifra el mensaje con la clave secreta, y la
			 * clave secreta con la clave publica
			 */
			long startTime = System.nanoTime();
			byte[] mensajeEnc = encrypt(secKey, iv, mensaje, ALGORITMOS[1], BLOCKSPADDING[0]);
			long endTime = System.nanoTime();
			double tiempoCifrado = (endTime - startTime) / (1000000.0);

			/* Descifra el mensaje cifrado */
			startTime = System.nanoTime();
			String mensajeFinal = decrypt(secKey, iv, mensajeEnc, ALGORITMOS[1], BLOCKSPADDING[0]);
			endTime = System.nanoTime();
			double tiempoDescifrado = (endTime - startTime) / (1000000.0);

			tiempoMedioCifrado += tiempoCifrado;
			tiempoMedioDescifrado += tiempoDescifrado;

		}
		tiempoMedioCifrado = tiempoMedioCifrado / veces;
		tiempoMedioDescifrado = tiempoMedioDescifrado / veces;

		System.out.println("Tiempo medio cifrado con clave secreta de " + veces + " documentos:\t\t"
				+ df.format(tiempoMedioDescifrado) + " ms.");
		System.out.println("Tiempo medio descifrado con clave secreta de " + veces + " documentos:\t\t"
				+ df.format(tiempoMedioDescifrado) + " ms.");
		System.out.println();
		
		/* Cifrado y descifrado con clave publica/privada */
		tiempoMedioCifrado = 0.0;
		tiempoMedioDescifrado = 0.0;
		System.out
				.println("Calculando tiempos de encriptacion de mensajes aleatorios con clave publica/privada...");
		for (int i = 0; i < veces; i++) {

			/* Genera un mensaje random */
			String mensaje = generateRandomString(KEY_LENGTHS[2]);

			/*
			 * Cifra el mensaje con la clave secreta, y la
			 * clave secreta con la clave publica
			 */
			long startTime = System.nanoTime();
			byte[] mensajeEnc = encrypt(pub, mensaje, ALGORITMOS[2], BLOCKSPADDING[1]);
			long endTime = System.nanoTime();
			double tiempoCifrado = (endTime - startTime) / (1000000.0);

			/* Descifra el mensaje cifrado */
			startTime = System.nanoTime();
			String mensajeFinal = decrypt(pri, mensajeEnc, ALGORITMOS[2], BLOCKSPADDING[1]);
			endTime = System.nanoTime();
			double tiempoDescifrado = (endTime - startTime) / (1000000.0);

			tiempoMedioCifrado += tiempoCifrado;
			tiempoMedioDescifrado += tiempoDescifrado;

		}
		tiempoMedioCifrado = tiempoMedioCifrado / veces;
		tiempoMedioDescifrado = tiempoMedioDescifrado / veces;

		System.out.println("Tiempo medio cifrado con clave publica de " + veces + " documentos:\t\t"
				+ df.format(tiempoMedioDescifrado) + " ms.");
		System.out.println("Tiempo medio descifrado con clave publica de " + veces + " documentos:\t\t"
				+ df.format(tiempoMedioDescifrado) + " ms.");
	}

	public static X509Certificate generateCertificate(KeyPair keyPair, String alg)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException {
		X509V3CertificateGenerator cert = new X509V3CertificateGenerator();
		cert.setSerialNumber(BigInteger.valueOf(1)); // or generate a random
														// number
		cert.setSubjectDN(new X509Principal("CN=localhost")); // see examples to
																// add O,OU etc
		cert.setIssuerDN(new X509Principal("CN=localhost")); // same since it is
																// self-signed
		cert.setPublicKey(keyPair.getPublic());
		Calendar c1 = new GregorianCalendar();
		c1.set(2015, 12, 14);
		Calendar c2 = new GregorianCalendar();
		c2.set(2016, 12, 14);
		cert.setNotBefore(c1.getTime());
		cert.setNotAfter(c2.getTime());
		cert.setSignatureAlgorithm(alg);
		PrivateKey signingKey = keyPair.getPrivate();
		return cert.generate(signingKey);
	}

	private static double hashTest(String msg, String alg) throws NoSuchAlgorithmException {

		if (debug) {
			System.out.println("=-=-=-=Hash de un mensaje=-=-=-=");
			System.out.println("Comienzo del hasheo");
			System.out.println("Hasheando...");
		}
		/* Mide el tiempo de hash del mensaje */
		long startTime = System.nanoTime();
		String hash = SecurityUtils.hashMsg(msg, alg);
		long endTime = System.nanoTime();
		double duration = (endTime - startTime) / (1000000.0);

		if (debug) {
			System.out.println("Hasheo completado");
			System.out.println("Mensaje original:\t" + MENSAJE);
			System.out.println("Mensaje hasheado:\t" + hash);
			System.out.println("Tiempo de ejecución de hasheo: " + duration + " milisegundos");
			System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		}

		return duration;
	}

	private static double secretKeyTest(int keyLength, String alg, KeyStore ks, boolean store)
			throws KeyStoreException {

		/* Criptografia de clave secreta */
		if (debug) {
			System.out.println("=-=-=-=Clave secreta=-=-=-=");
			System.out.println("Comienzo de generación de clave secreta");
			System.out.println("Generando...");
		}

		/* Mide el tiempo de generacion de la clave secreta */
		long startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(keyLength, alg);
		long endTime = System.nanoTime();
		double duration = (endTime - startTime) / (1000000.0);

		if (debug) {
			System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");
			System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		}

		/* Almacena clave secreta */
		if (store) {
			KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
			ks.setEntry("secretkey", skEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
		}
		return duration;
	}

	private static double privatePublicKeyTest(int keyLength, String alg, String algCert, KeyStore ks, boolean store)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, KeyStoreException {

		/* Criptografia de clave publica/privada */
		if (debug) {
			System.out.println("=-=-=-=Clave publica/privada=-=-=-=");
			System.out.println("Comienzo de generación de clave privada y clave pública");
			System.out.println("Generando...");
		}

		/* Mide el tiempo de generacion del par de claves publica/privada */
		long startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(keyLength, alg);
		long endTime = System.nanoTime();
		double duration = (endTime - startTime) / (1000000.0);

		if (debug) {
			System.out.println(
					"Tiempo de ejecución de generación de clave publica" + "y privada: " + duration + " milisegundos");
			System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		}

		/* Almacena el par de claves publica/privada */
		if (store) {
			X509Certificate certificate = generateCertificate(keyPair, algCert);
			Certificate[] certChain = new Certificate[1];
			certChain[0] = certificate;
			pub = keyPair.getPublic();
			ks.setKeyEntry("privatekey", (Key) keyPair.getPrivate(), PASSWORD.toCharArray(), certChain);
		}
		return duration;
	}

	/**
	 * @return el tiempo que ha costado encriptar el texto
	 */
	private static byte[] encrypt(PublicKey puKey, String msg, String alg, String pad) throws Exception {

		/* Cifra el mensaje con la clave publica */
		Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher.init(Cipher.ENCRYPT_MODE, puKey);
		byte[] cipherText = cipher.doFinal(msg.getBytes("UTF8"));
		return cipherText;
	}

	/** 
	 * @return el tiempo que ha costado encriptar el texto
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static byte[] encrypt(SecretKey secK, IvParameterSpec iv, String msg, String alg, String pad)
			throws Exception {

		/* Cifra el mensaje con la clave secreta */
		Cipher cipher = Cipher.getInstance(alg + pad);
		cipher.init(Cipher.ENCRYPT_MODE, secK, iv);
		byte[] cipherText = cipher.doFinal(msg.getBytes("UTF8"));
		return cipherText;
	}

	/**
	 * @return el tiempo que ha costado encriptar el texto
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static String decrypt(PrivateKey prKey, byte[] msg, String alg, String pad)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {

		/* Descifra el mensaje con la clave privada */
		Cipher cipher2 = Cipher.getInstance("RSA/ECB/PKCS1Padding");
		cipher2.init(Cipher.DECRYPT_MODE, prKey);
		byte[] cipherText = cipher2.doFinal(msg);
		return new String(cipherText, "UTF8");
	}

	/**
	 * @return el tiempo que ha costado encriptar el texto
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static String decrypt(SecretKey secK, IvParameterSpec iv, byte[] msg, String alg, String pad)
			throws Exception {

		/* Descifra el mensaje con la clave privada */
		Cipher cipher2 = Cipher.getInstance(alg + pad);
		cipher2.init(Cipher.DECRYPT_MODE, secK, iv);
		byte[] cipherText = cipher2.doFinal(msg);
		return new String(cipherText, "UTF8");
	}

	/**
	 * @return el tiempo que ha costado generar la firma digital
	 */
	private static double digitalSignatureTest(PublicKey pub, PrivateKey priv) {

		if (debug) {
			System.out.println("=-=-=-=Firma digital=-=-=-=");
			System.out.println("Comienzo de creacion de firma digital");
			System.out.println("Firmando...");
		}

		/* Mide el tiempo de generacion de la firma digital */
		long startTime = System.nanoTime();
		/* No pasa nada por no usar la variable firma */
		@SuppressWarnings("unused")
		Signature firma = SecurityUtils.createDigitalSignature(MENSAJE, pub, priv, ALGORITMOS[0], ALGORITMOS[3], debug);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);

		if (debug) {
			System.out.println("Tiempo de ejecución de creacion de firma digital: " + duration + " milisegundos");
			System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		}
		return duration;
	}

	private static String leerFichero(File file) throws FileNotFoundException {

		String contenidoFichero = "";
		Scanner leer = new Scanner(file);

		while (leer.hasNextLine()) {
			contenidoFichero += leer.nextLine();
		}
		leer.close();
		return contenidoFichero;
	}

	public static String generateRandomString(int keyLengthUsed) {
		int realSize = (keyLengthUsed / 8) - 11;
		String uuid = UUID.randomUUID().toString();

		while (uuid.length() < realSize) {
			uuid = uuid + UUID.randomUUID().toString();
		}

		if (uuid.length() > realSize) {
			uuid = uuid.substring(0, realSize);
		}
		return uuid;
	}
}
