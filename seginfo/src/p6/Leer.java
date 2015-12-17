package p6;

import java.util.Scanner;

public class Leer {

	public static void main(String[] args) {
		//Variables
		boolean v = false;
		boolean c = false;
		boolean[] e = new boolean[3];
		
		// Leer argumentos
		for (int i = 0; i < args.length; i++) {
			if(args[i].equals("-v")){
				v = true;
			}
			else if(args[i].equals("-c")){
				c = true;
			}
			else if(args[i].equals("-e")){
				if(i+1!=args.length && args[i+1].equals("SQL")){
					e[0] = true;
				}
				else if(i+1!=args.length && args[i+1].equals("HTML")){
					e[1] = true;
				}
				else if(i+1!=args.length && args[i+1].equals("URL")){
					e[2] = true;
				}
			}
		}
		
		if(args.length==0){
			System.err.println("Uso incorrecto del programa.");
			System.out.println("Uso del programa: leer [-v|-c] {-e[SQL|HTML|URL]}*");
		}
		
		// Funcionamiento principal del programa
		Scanner s = new Scanner(System.in);
		String input = s.nextLine();
		
		// Valida
		if(v){
			// TODO
		}
		
		// Canonicaliza
		if(c){
			// TODO
		}
		
		// Codifica
		if(e[0] || e[1] || e[2]){
			// TODO
		}
	}
}
