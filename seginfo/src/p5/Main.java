package p5;

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.sql.Date;
import java.util.Calendar;
import java.util.GregorianCalendar;

import org.bouncycastle.jce.X509Principal;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.SecretKey;

/**
 * 
 * @author Alejandro Royo Amondarain (NIP: 560285) Jaime Ruiz-Borau Vizárraga
 *         (NIP: 546751)
 *
 *         Esta clase contiene el codigo correspondiente a las pruebas y medida
 *         de tiempos de los diferentes metodos de hash, encriptacion y firma
 *         digital solicitados en el guion de la practica 5 de Seguridad
 *         Informatica.
 */
@SuppressWarnings({ "deprecation", "unused" })
public class Main {

	final private static int[] KEY_LENGTHS = { 56, 512 };
	final private static String[] ALGORITMOS = { "SHA-256", "DES", "RSA", "SHA256withRSA" };
	final private static String MENSAJE = "VIVA PIT";
	final private static String PASSWORD = "VIVAPODEMOS";

	public static void main(String[] args) throws KeyStoreException, InvalidKeyException, IllegalStateException,
			NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, IOException {

		/* Hash del mensaje */
		System.out.println("Comienzo del hasheo");
		System.out.println("Hasheando...");
		long startTime = System.nanoTime();
		String hash = SecurityUtils.hashMsg(MENSAJE, ALGORITMOS[0]);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de hasheo: " + duration + " milisegundos");

		/* Creacion del almacen de claves */
		KeyStore ks = null;
		try {
			ks = KeyStore.getInstance("JCEKS");
			ks.load(null, PASSWORD.toCharArray());
		} catch (KeyStoreException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (CertificateException e) {
			e.printStackTrace();
			System.exit(0);
		} catch (IOException e) {
			e.printStackTrace();
			System.exit(0);
		}

		/* Criptografia de clave secreta */
		System.out.println("Comienzo de generación de clave secreta");
		System.out.println("Generando...");
		startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(KEY_LENGTHS[0], ALGORITMOS[1]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");
		// Almacenar clave secreta
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
		try {
			ks.setEntry("claveSecreta", skEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
		} catch (KeyStoreException e) {
			e.printStackTrace();
		}

		/* Criptografia de clave publica */
		System.out.println("Comienzo de generación de clave privada y clave pública");
		System.out.println("Generando...");
		startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(KEY_LENGTHS[1], ALGORITMOS[2]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out
				.println("Tiempo de ejecución de generación de clave publica y privada: " + duration + " milisegundos");
		// Almacenar clave secreta
		X509Certificate certificate = generateCertificate(keyPair, ALGORITMOS[3]);
		KeyStore keyStore = KeyStore.getInstance("JKS");
		keyStore.load(null, null);
		Certificate[] certChain = new Certificate[1];
		certChain[0] = certificate;
		keyStore.setKeyEntry("privatekey", (Key) keyPair.getPrivate(), PASSWORD.toCharArray(), certChain);

		/* Firma digital */
		System.out.println("Comienzo de creación de firma digital");
		System.out.println("Firmando...");
		startTime = System.nanoTime();
		Signature firma = SecurityUtils.createDigitalSignature(MENSAJE, keyPair, ALGORITMOS[0], ALGORITMOS[3]);
		endTime = System.nanoTime();
		duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de creación de firma digital: " + duration + " milisegundos");

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
}
