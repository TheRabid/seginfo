package p5;

import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyStore;
import java.security.KeyStore.Entry;
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
import org.bouncycastle.x509.X509V3CertificateGenerator;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
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
/**
 * @author Jaime
 *
 */
@SuppressWarnings("deprecation")
public class Main {

	final private static int[] KEY_LENGTHS = { 56, 512 };
	final private static String[] ALGORITMOS = { "SHA-256", "DES", "RSA", "SHA256withRSA" };
	final private static String MENSAJE = "VIVA PIT";
	final private static String PASSWORD = "VIVAPODEMOS";
	private static PublicKey pub = null;

	@SuppressWarnings("unused")
	public static void main(String[] args) throws KeyStoreException, InvalidKeyException, IllegalStateException,
			NoSuchProviderException, NoSuchAlgorithmException, SignatureException, CertificateException, IOException,
			NoSuchPaddingException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException {

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
		encryptTextTest(secrEntry.getSecretKey(),secrEntry.getSecretKey(), MENSAJE, ALGORITMOS[1]);
		
		/* Criptografia de clave publica/privada */
		double durationPrivPubKey = privatePublicKeyTest(KEY_LENGTHS[1], ALGORITMOS[2], ALGORITMOS[3], ks);
		PrivateKey pri = (PrivateKey) ks.getKey("privatekey", PASSWORD.toCharArray());

		// Cifrar mensaje de prueba
		encryptTextTest(pub, pri, MENSAJE, ALGORITMOS[2]);

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
	 * y 160 bits respectivamente, esta implementación proporciona una mayor
	 * seguridad.
	 * 
	 * @return el tiempo que ha costado hashear el mensaje
	 * @throws NoSuchAlgorithmException
	 *             Si el algoritmo no existe
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
		System.out.println("Tiempo de ejecución de hasheo: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}

	/**
	 * Para la generación de una clave secreta... TODO
	 * 
	 * @return el tiempo que ha costado generar la clave secreta
	 * @throws KeyStoreException
	 *             si no se puede almacenar la clave
	 */
	private static double secretKeyTest(int keyLength, String alg, KeyStore ks) throws KeyStoreException {
		/* Criptografia de clave secreta */
		System.out.println("=-=-=-=Clave secreta=-=-=-=");
		System.out.println("Comienzo de generación de clave secreta");
		System.out.println("Generando...");
		long startTime = System.nanoTime();
		SecretKey secretKey = SecurityUtils.generateSecretKey(keyLength, alg);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de generación de clave secreta: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		// Almacenar clave secreta
		KeyStore.SecretKeyEntry skEntry = new KeyStore.SecretKeyEntry(secretKey);
		ks.setEntry("secretkey", skEntry, new KeyStore.PasswordProtection(PASSWORD.toCharArray()));
		return duration;
	}

	/**
	 * Para la generación de una clave privada y publica... TODO
	 * 
	 * @return el tiempo que ha costado generar la clave privada/publica
	 */
	private static double privatePublicKeyTest(int keyLength, String alg, String algCert, KeyStore ks)
			throws CertificateEncodingException, InvalidKeyException, IllegalStateException, NoSuchProviderException,
			NoSuchAlgorithmException, SignatureException, KeyStoreException {
		/* Criptografia de clave publica/privada */
		System.out.println("=-=-=-=Clave publica/privada=-=-=-=");
		System.out.println("Comienzo de generación de clave privada y clave pública");
		System.out.println("Generando...");
		long startTime = System.nanoTime();
		KeyPair keyPair = SecurityUtils.generatePrivatePublicKey(keyLength, alg);
		long endTime = System.nanoTime();
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out
				.println("Tiempo de ejecución de generación de clave publica y privada: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		// Almacenar clave secreta
		X509Certificate certificate = generateCertificate(keyPair, algCert);
		Certificate[] certChain = new Certificate[1];
		certChain[0] = certificate;
		pub = keyPair.getPublic();
		System.out.println(keyPair.toString());
		System.out.println(keyPair.getPrivate().toString());
		System.out.println(certChain.toString());
		ks.setKeyEntry("privatekey", (Key)keyPair.getPrivate(), PASSWORD.toCharArray(), certChain);  
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
	 */
	private static double encryptTextTest(Key puKey, Key prKey, String msg, String alg)
			throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException,
			BadPaddingException, UnsupportedEncodingException {
		System.out.println("=-=-=-=Encriptar texto=-=-=-=");
		System.out.println("Comienzo de encriptado");
		System.out.println("Encriptando...");
		long startTime = System.nanoTime();
		Cipher cipher = Cipher.getInstance(alg);
		cipher.init(Cipher.ENCRYPT_MODE, puKey);
		byte[] cipherText = cipher.doFinal(msg.getBytes());
		long endTime = System.nanoTime();
		System.out.println("Finalizado el encriptado:\t" + (new String(cipherText, "UTF8")));
		System.out.println("Desencriptando para certificar");
		cipher.init(Cipher.DECRYPT_MODE, prKey);
		byte[] newPlainText = cipher.doFinal(cipherText);
		System.out.println("Desencriptado: " + (new String(newPlainText, "UTF8")));
		long duration = (endTime - startTime) / (long) (1000000.0);
		System.out.println("Tiempo de ejecución de cifrado de texto: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}

	/**
	 * Para la generación de la firma digital... TODO
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
		System.out.println("Tiempo de ejecución de creacion de firma digital: " + duration + " milisegundos");
		System.out.println("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=");
		return duration;
	}
}
