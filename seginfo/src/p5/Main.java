package p5;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
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
import java.security.UnrecoverableEntryException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.GregorianCalendar;
import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

/**
 * 
 * @author Alejandro Royo Amondarain (NIP: 560285) Jaime Ruiz-Borau Viz�rraga
 *         (NIP: 546751)
 *
 *         Esta clase contiene el codigo correspondiente a las pruebas y medida
 *         de tiempos de los diferentes metodos de hash, encriptacion y firma
 *         digital solicitados en el guion de la practica 5 de Seguridad
 *         Informatica.
 */

@SuppressWarnings("deprecation")
public class Main {

	final private static int[] KEY_LENGTHS = { 128, 1024 };
	final private static String[] ALGORITMOS = { "SHA-256", "AES", "RSA", "SHA256withRSA" };
	final private static String[] BLOCKSPADDING = { "/PCBC/PKCS5Padding", "/ECB/PKCS1Padding" };
	final private static String MENSAJE = "VIVA PITAAAAAAAAAAAAAAAAAAAAAAAAAAA";
	final private static String PASSWORD = "VIVAPODEMOS";
	private static PublicKey pub = null;

	@SuppressWarnings("unused")
	public static void main(String[] args) throws KeyStoreException, InvalidKeyException, IllegalStateException,
			NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException,
			InvalidAlgorithmParameterException {

		/* Hash */
		double durationHash = hashTest(MENSAJE, ALGORITMOS[0]);

		/* Creacion del almacen de claves */
		KeyStore ks = null;
		ks = KeyStore.getInstance("JCEKS");
		ks.load(null, PASSWORD.toCharArray());
		KeyStore.ProtectionParameter protParam = new KeyStore.PasswordProtection(PASSWORD.toCharArray());

		/* Generar clave secreta */
		double durationSecretKey = secretKeyTest(KEY_LENGTHS[0], ALGORITMOS[1], ks);
		KeyStore.SecretKeyEntry secrEntry = (KeyStore.SecretKeyEntry) ks.getEntry("secretkey", protParam);

		/* Test encriptado clave secreta */
		System.out.println("=====TEST ENCRIPTADO CLAVE SECRETA=====");
		encryptTextTest(secrEntry.getSecretKey(), secrEntry.getSecretKey(), MENSAJE, ALGORITMOS[1], BLOCKSPADDING[0]);

		/* Criptografia de clave publica/privada */
		double durationPrivPubKey = privatePublicKeyTest(KEY_LENGTHS[1], ALGORITMOS[2], ALGORITMOS[3], ks);
		PrivateKey pri = (PrivateKey) ks.getKey("privatekey", PASSWORD.toCharArray());

		// Cifrar mensaje de prueba
		encryptTextTest(pub, pri, MENSAJE, ALGORITMOS[2], BLOCKSPADDING[1]);

		/* Firma digital */
		double durationDigitalSignature = digitalSignatureTest(pub, pri);

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

	/**
	 * Para el hasheo de un mensaje, se ha empleado la clase MessageDigest. Se
	 * ha optado por el empleo de un algoritmo SHA-256 ya que produce una
	 * "huella digital" de 256 bits.
	 * 
	 * Como habitualmente se emplean los algoritmos MD5 y SHA-1, que son de 128
	 * y 160 bits respectivamente, esta implementaci�n proporciona una mayor
	 * seguridad.
	 */
	private static double hashTest(String msg, String alg) throws NoSuchAlgorithmException {
		/* Hash del mensaje */
		System.out.println("=-=-=-=Hash de un mensaje=-=-=-=");
		System.out.println("Comienzo del hasheo");
		System.out.println("Hasheando...");
		long startTime = System.nanoTime();
		String hash = SecurityUtils.hashMsg(msg, alg);
		long endTime = System.nanoTime();
		System.out.println("Hasheo completado");
		System.out.println("Mensaje original:\t" + MENSAJE);
		System.out.println("Mensaje hasheado:\t" + hash);
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecuci�n de hasheo: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}

	/**
	 * Para la generaci�n de una clave secreta... TODO
	 * 
	 */
	private static double secretKeyTest(int keyLength, String alg, KeyStore ks) throws KeyStoreException {
		/* Criptografia de clave secreta */
		System.out.println("=-=-=-=Clave secreta=-=-=-=");
		System.out.println("Comienzo de generaci�n de clave secreta");
		System.out.println("Generando...");
		long startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(keyLength, alg);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecuci�n de generaci�n de clave secreta: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		// Almacenar clave secreta
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
		ks.setEntry("secretkey", skEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
		return duration;
	}

	/**
	 * Para la generaci�n de una clave privada y publica... TODO
	 * 
	 * @return el tiempo que ha costado generar la clave privada/publica
	 */
	private static double privatePublicKeyTest(int keyLength, String alg, String algCert, KeyStore ks)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, KeyStoreException {
		/* Criptografia de clave publica/privada */
		System.out.println("=-=-=-=Clave publica/privada=-=-=-=");
		System.out.println("Comienzo de generaci�n de clave privada y clave p�blica");
		System.out.println("Generando...");
		long startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(keyLength, alg);

		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out
				.println("Tiempo de ejecuci�n de generaci�n de clave publica y privada: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		// Almacenar clave secreta
		X509Certificate certificate = generateCertificate(keyPair, algCert);
		Certificate[] certChain = new Certificate[1];
		certChain[0] = certificate;
		pub = keyPair.getPublic();
		ks.setKeyEntry("privatekey", (Key) keyPair.getPrivate(), PASSWORD.toCharArray(), certChain);
		return duration;
	}

	/**
	 * Para la encriptacion del texto... TODO
	 * 
	 * @return el tiempo que ha costado encriptar el texto
	 * @throws NoSuchPaddingException
	 * @throws NoSuchAlgorithmException
	 * @throws InvalidKeyException
	 * @throws BadPaddingException
	 * @throws IllegalBlockSizeException
	 * @throws UnsupportedEncodingException
	 * @throws InvalidAlgorithmParameterException
	 */
	private static double encryptTextTest(Key puKey, Key prKey, String msg, String alg, String pad)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException, InvalidAlgorithmParameterException {
		System.out.println("=-=-=-=Encriptar texto=-=-=-=");
		System.out.println("Comienzo de encriptado");
		System.out.println("Encriptando...");
		String initVector = "RandomInitVector"; // 16 bytes IV
		IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
		Cipher cipher = Cipher.getInstance(alg + pad);
		if (puKey instanceof PublicKey) {
			cipher.init(Cipher.ENCRYPT_MODE, puKey);
		} else {
			cipher.init(Cipher.ENCRYPT_MODE, puKey, iv);
		}
		String finalEncrypt = "";
		long startTime = System.nanoTime();
		// for (int i = 0; i < msg.length(); i += 16) {
		// byte[] cipherText = null;
		// if (i + 16 >= msg.length()) {
		// if (msg.length() % 16 != 0) {
		// System.out.println(msg.length() % 128);
		// for (int p = 0; p < msg.length() % 128; p++) {
		// msg = msg + " ";
		// }
		// }
		// cipherText = cipher.doFinal(msg.substring(i,
		// msg.length()).getBytes());
		// } else {
		// cipherText = cipher.doFinal(msg.substring(i, i + 128).getBytes());
		// }
		// finalEncrypt = finalEncrypt + new String(cipherText, "UTF8");
		// }
		byte[] cipherText = cipher.doFinal(msg.getBytes());
		long endTime = System.nanoTime();
		finalEncrypt = new String(cipherText, "UTF8");
		System.out.println("Finalizado el encriptado:\t" + finalEncrypt);
		System.out.println("Desencriptando para certificar");
		Cipher cipher2 = Cipher.getInstance(alg + pad);
		if (puKey instanceof PublicKey) {
			cipher2.init(Cipher.DECRYPT_MODE, prKey);
		} else {
			cipher2.init(Cipher.DECRYPT_MODE, prKey, iv);
		}
		String finalDeEncrypt = "";
		// for (int i = 0; i < finalEncrypt.length(); i += 128) {
		// byte[] newPlainText = null;
		// if(i+128>=msg.length()){
		// newPlainText =
		// cipher.doFinal(finalEncrypt.substring(i,finalEncrypt.length()).getBytes());
		// }
		// else{
		// newPlainText =
		// cipher.doFinal(finalEncrypt.substring(i,i+128).getBytes());
		// }
		// finalDeEncrypt = finalDeEncrypt + new String(newPlainText, "UTF8");
		// }
		finalDeEncrypt = new String(cipher2.doFinal(cipherText), "UTF8");
		System.out.println("Desencriptado: " + finalDeEncrypt);
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecuci�n de cifrado de texto: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}

	public static String encrypt(Key key, String value) {
		try {
			Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
			cipher.init(Cipher.ENCRYPT_MODE, key);

			byte[] encrypted = cipher.doFinal(value.getBytes());
			System.out.println("encrypted string: " + Base64.toBase64String(encrypted));

			return Base64.toBase64String(encrypted);
		} catch (Exception ex) {
			ex.printStackTrace();
		}

		return null;
	}

	// public static String decrypt(Key key, String initVector, String
	// encrypted) {
	// try {
	// IvParameterSpec iv = new IvParameterSpec(initVector.getBytes("UTF-8"));
	// SecretKeySpec skeySpec = new SecretKeySpec(key.getBytes("UTF-8"), "AES");
	//
	// Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5PADDING");
	// cipher.init(Cipher.DECRYPT_MODE, skeySpec, iv);
	//
	// byte[] original = cipher.doFinal(Base64.decodeBase64(encrypted));
	//
	// return new String(original);
	// } catch (Exception ex) {
	// ex.printStackTrace();
	// }
	//
	// return null;
	// }

	/**
	 * Para la generaci�n de la firma digital... TODO
	 * 
	 * @return el tiempo que ha costado generar la firma digital
	 */
	private static double digitalSignatureTest(PublicKey pub, PrivateKey priv) {
		System.out.println("=-=-=-=Firma digital=-=-=-=");
		System.out.println("Comienzo de creacion de firma digital");
		System.out.println("Firmando...");
		long startTime = System.nanoTime();
		Signature firma = SecurityUtils.createDigitalSignature(MENSAJE, pub, priv, ALGORITMOS[0], ALGORITMOS[3]);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecuci�n de creacion de firma digital: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}
}
