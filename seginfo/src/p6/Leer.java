package p6;

import java.util.Scanner;
import org.owasp.esapi.ESAPI;
import org.owasp.esapi.Encoder;
import org.owasp.esapi.codecs.MySQLCodec;
import org.owasp.esapi.errors.EncodingException;
import org.owasp.esapi.reference.DefaultValidator;

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
					input = enc.canonicalize(input);
					System.out.println("Canonizado: " + input);
				}

				// Valida
				if (v) {
					boolean b = val.isValidInput(formulario[i], input, properties[i], 50, false);
					if (b)
						System.out.print("E");
					else
						System.out.print("No e");
					System.out.println("s valido");
				}

				// Codifica
				if (e[0] || e[1] || e[2]) {

					// SQL
					if (e[0]) {
						System.out.println("Codificacion para MySQL: ");
						MySQLCodec codec = new MySQLCodec(MySQLCodec.Mode.STANDARD);
						System.out.println(ESAPI.encoder().encodeForSQL(codec, input));
						System.out.println();
					}

					// URL
					if (e[1]) {
						System.out.println("Codificacion para URL: ");
						try {
							System.out.println(ESAPI.encoder().encodeForURL(input));
						} catch (EncodingException e1) {
							System.out.println("ERROR: No se pudo codificar \"" + input + "\" en formato URL");
						}
						System.out.println();
					}

					// HTML
					if (e[2]) {
						System.out.println("Codificacion para HTML: ");
						System.out.println(ESAPI.encoder().encodeForHTML(input));
						System.out.println();
					}
				}
				System.out.println();
				System.out.println("===============");
				System.out.println();
			}
		}

	}
}
