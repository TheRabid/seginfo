package p6;

import java.util.Scanner;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.Validator;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.reference.DefaultValidator;

/**
 * 
 * @author Alejandro Royo Amondarain (NIP: 560285) Jaime Ruiz-Borau Vizarraga
 *         (NIP: 546751)
 *
 *         Clase Leer. Contiene el funcionamiento principal del programa
 *         solicitado en el guion de la practica 6.
 * 
 *         Es necesario que esten definidos en el fichero ESAPI.properties y
 *         validation.properties las siguientes reglas especiales:
 * 
 *         Validator.Nombre=^[A-Za-z0-9'-. (?=&)]{0,50}$
 *         Validator.Direccion=^[A-Za-z0-9'-,. (?=&)/º]{0,50}$
 *         Validator.TC=^[0-9]{16}$ 
 *         Validator.TipoTC=^(MC|VISA|AMEX)$
 *         Validator.MesExpiraTC=^[0-9]{2}$ 
 *         Validator.AnyoExpiraTC=^[0-9]{4}$
 *         Validator.CVNTC=^[0-9]{3}$ 
 *         Validator.DNI=^[0-9]{8}[A-Z]{1}$
 */

public class Leer {

	public static void main(String[] args) throws EncodingException {
		// Variables
		boolean v = false;
		boolean c = false;
		boolean[] e = new boolean[3];

		// Leer argumentos
		for (int i = 0; i < args.length; i++) {
			if (args[i].equals("-v")) {
				v = true;
			} else if (args[i].equals("-c")) {
				c = true;
			} else if (args[i].equals("-e")) {
				if (i + 1 != args.length && args[i + 1].equals("SQL")) {
					e[0] = true;
				} else if (i + 1 != args.length && args[i + 1].equals("HTML")) {
					e[1] = true;
				} else if (i + 1 != args.length && args[i + 1].equals("URL")) {
					e[2] = true;
				}
			}
		}

		if (args.length == 0) {
			System.err.println("Uso incorrecto del programa.");
			System.out.println("Uso del programa: leer [-v|-c] {-e[SQL|HTML|URL]}*");
		} else {
			// String[] con el formulario
			String[] formulario = { "Nombre", "Direccion", "Tipo tarjeta credito", "Numero tarjeta credito",
					"Mes expira tarjeta credito", "Ano expira tarjeta credito", "CVN tarjeta credito", "DNI" };
			String[] datos = new String[8];
			String[] properties = { "Nombre", "Direccion", "TipoTC", "TC", "MesExpiraTC", "AnyoExpiraTC", "CVNTC",
					"DNI" };

			// Funcionamiento principal del programa
			System.out.println("===== Formulario del programa Leer =====");
			Scanner s = new Scanner(System.in);
			for (int i = 0; i < formulario.length; i++) {
				System.out.println(formulario[i]);
				String input = s.nextLine();
				datos[i] = input;
			}
			s.close();
			System.err.close();

			Encoder enc = ESAPI.encoder();
			DefaultValidator val = new DefaultValidator(enc);
			for (int i = 0; i < datos.length; i++) {
				String input = datos[i];
				System.out.println("===== " + formulario[i] + " =====");

				// Canonicaliza
				if (c) {
					canonizar(enc, input);
				}

				// Valida
				if (v) {
					validar(formulario, properties, i, input, val);
				}

				// Codifica
				if (e[0] || e[1] || e[2]) {

					// SQL
					if (e[0]) {
						codificarMySQL(input);
					}

					// URL
					if (e[1]) {
						codificarURL(input);
					}

					// HTML
					if (e[2]) {
						codificarHTML(input);
					}
				}
				System.out.println("============" + relleno(formulario[i].length()));
				System.out.println();
			}
		}
	}

	/**
	 * Metodo auxiliar para encapsular la canonizacion
	 * 
	 * @param enc
	 *            : Encoder empleado
	 * @param input
	 *            : Entrada a canonizar
	 */
	private static void canonizar(Encoder enc, String input) {
		input = enc.canonicalize(input);
		System.out.println("Canonizado: " + input);
	}

	/**
	 * Metodo auxiliar para encapsular la validacion
	 * 
	 * @param formulario
	 *            : Parametro auxiliar para mostrar informacion adicional por
	 *            pantalla (no relevante)
	 * @param properties
	 *            : Parametro auxiliar para mostrar informacion adicional por
	 *            pantalla (no relevante)
	 * @param i
	 *            : Parametro auxiliar para mostrar informacion adicional por
	 *            pantalla (no relevante)
	 * @param input
	 *            : Entrada a validar
	 * @param val
	 *            : Validator empleado
	 */
	private static void validar(String[] formulario, String[] properties, int i, String input, Validator val) {
		boolean b = val.isValidInput(formulario[i], input, properties[i], 50, false);
		if (b)
			System.out.print("E");
		else
			System.out.print("No e");
		System.out.println("s valido");
	}

	/**
	 * Metodo auxiliar para encapsular codificacion MySQL
	 * 
	 * @param input
	 *            : Entrada a codificar
	 */
	private static void codificarMySQL(String input) {
		System.out.println("Codificacion para MySQL: ");
		MySQLCodec codec = new MySQLCodec(MySQLCodec.Mode.STANDARD);
		System.out.println(ESAPI.encoder().encodeForSQL(codec, input));
		System.out.println();
	}

	/**
	 * Metodo auxiliar para encapsular codificacion URL
	 * 
	 * @param input
	 *            : Entrada a codificar
	 */
	private static void codificarURL(String input) {
		System.out.println("Codificacion para URL: ");
		try {
			System.out.println(ESAPI.encoder().encodeForURL(input));
		} catch (EncodingException e1) {
			System.out.println("ERROR: No se pudo codificar \"" + input + "\" en formato URL");
		}
		System.out.println();
	}

	/**
	 * Metodo auxiliar para encapsular codificacion HTML
	 * 
	 * @param input
	 *            : Entrada a codificar
	 */
	private static void codificarHTML(String input) {
		System.out.println("Codificacion para HTML: ");
		System.out.println(ESAPI.encoder().encodeForHTML(input));
		System.out.println();
	}

	/**
	 * Metodo auxiliar para mostrar por pantalla mejor la informacion
	 * 
	 * @param num
	 *            : numero de simbolos '=' solicitados
	 * 
	 * @return String con numero 'num' de simbolos '='
	 */
	private static String relleno(int num) {
		String returned = "";
		for (int i = 0; i < num; i++) {
			returned = returned + "=";
		}
		return returned;
	}
}
