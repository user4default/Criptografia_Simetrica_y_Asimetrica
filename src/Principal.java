import java.io.IOException;
import java.util.Scanner;

import org.bouncycastle.crypto.InvalidCipherTextException;

public class Principal {
	
	public static void main(String[] args) throws IOException, InvalidCipherTextException {
		Scanner sc = new Scanner(System.in); // Abrimos el Scanner al principio para evitar problemas, lo cerramos al final del programa
		Simetrica simetric = new Simetrica(); // Objeto para realizar las funciones de criptografia SIMETRICA
		Asimetrica asimetric = new Asimetrica(); // Objeto para realizar las funciones de criptografia ASIMETRICA
		int opcion;	
		do {
			System.out.println("\n¿Que tipo de criptografia desea utilizar?"
					+ "\n1. Simetrica"+"\n2. Asimetrica"+"\n3. Salir"); 
			switch(opcion = Integer.parseInt(sc.next())){ // Next guarda el retrono de carro
				case 1:
					menuSimetrica(sc,simetric);
				break;
				
				case 2:
					menuAsimetrica(sc,asimetric);	
				break;
			}//end switch
		}while(opcion!=3);
		
	}//end main
	
	public static void menuSimetrica(Scanner sc, Simetrica sim) throws IOException {
		int opcion;
		String nomFichKey, // Nombre del fichero con la CLAVE SECRETA
			nomFichSinCifrado, // Nombre del FICHERO en CLARO
				nomFichCifrado; // Nombre del FICHERO CIFRADO
		do {
			System.out.println("\nElija una opcion para CRIPTOGRAFIA SIMETRICA:"+"\n0. Volver al menu principal"+
			"\n1. Generar Clave"+"\n2. Cifrado"+"\n3. Descifrado");
			
			switch(opcion = Integer.parseInt(sc.next())){
				
			case 1:
					System.out.println("\nIntroduce un nombre para el fichero donde se guardara la CLAVE:");
					String nomFich = sc.next();
					try {
						sim.generarClave(nomFich);
					} catch (IOException e) {
						e.printStackTrace();
						} //end catch
				break;
				
			case 2:
					System.out.println("\nIntroduce el nombre del fichero con CLAVE:");
					nomFichKey = sc.next();
					System.out.println("\nIntroduce el nombre del fichero que desea CIFRAR:");
					nomFichSinCifrado = sc.next();
					System.out.println("\nIntroduce el nombre del fichero donde quiere guardar el fichero ya CIFRADO:");
					nomFichCifrado = sc.next();
					sim.cifrar(nomFichKey, nomFichSinCifrado, nomFichCifrado);
				break;
				
			case 3:
					System.out.println("\nIntroduce el nombre del fichero con la CLAVE:");
					nomFichKey = sc.next();					
					System.out.println("\nIntroduce el nombre del fichero que desea DESCIFRAR:");
					nomFichCifrado = sc.next();
					System.out.println("\nIntroduce el nombre del fichero donde quiere guardar el fichero ya DESCIFRADO:");
					nomFichSinCifrado = sc.next();
					sim.descifrar(nomFichKey,nomFichCifrado,nomFichSinCifrado);
				break;
			
			}//end switch
		}while(opcion!=0);
	}//end menuSimetrica
	
	public static void menuAsimetrica(Scanner sc, Asimetrica aSim) throws IOException, InvalidCipherTextException {
		int opcion; // Opcion que seleccione el usuario 
		String nomFichKp, // FICHERO con la CLAVE PUBLICA
				nomFichKs, // FICHERO con la CLAVE PRIVADA
					nomFichSinCifrado, // FICHERO NO CIFRADO 
 						nomFichCifrado, // FICHERO CIFRADO
						nomFichSinFirma, // FICHERO SIN FIRMAR 
					nomFichFirma, // FICHERO FIRMADO
				tipoCifrado, // tipo de CIFRADO que el usuario elija 
			nomFichKey; // Variable AUXILIAR para nombres de fichero
		
		do {
			System.out.println("\nElija una opcion para CRIPTOGRAFIA ASIMETRICA:"+"\n0. Volver al menu anterior"+
								"\n1. Generar pareja de claves"+"\n2. Cifrado"+"\n3. Descifrado"+"\n4. Firmar digitalmente"+"\n5. Verificar firma digital");
			
			switch(opcion = Integer.parseInt(sc.next())){ 
			
				case 1:
					System.out.println("\nNombre para el fichero con la CLAVE PRIVADA:");
					nomFichKs = sc.next();
					System.out.println("\nNombre para el fichero con la CLAVE PUBLICA:");
					nomFichKp = sc.next();
					aSim.generarClaves(nomFichKs, nomFichKp);
				break;
				
				case 2:
					System.out.println("\nIndique con que clave desea CIFRAR:");
					tipoCifrado = sc.next();
					System.out.println("\nIndique el fichero que contiene la CLAVE "+tipoCifrado.toUpperCase()+":");
					nomFichKey = sc.next();
					System.out.println("\nIndique el nombre del fichero a CIFRAR:");
					nomFichSinCifrado = sc.next();
					System.out.println("\nIndique el nombre del fichero ya CIFRADO:");
					nomFichCifrado = sc.next();
					aSim.cifrar(nomFichSinCifrado,nomFichKey,nomFichCifrado,tipoCifrado);
				break;
				
				case 3:
					System.out.println("\nIndique con que clave desea DESCIFRAR:");
					tipoCifrado = sc.next();
					System.out.println("\nIndique el fichero que contiene la CLAVE "+tipoCifrado.toUpperCase()+":");
					nomFichKey = sc.next();
					System.out.println("\nIndique el nombre del fichero CIFRADO:");
					nomFichCifrado = sc.next();
					System.out.println("\nIndique el nombre del fichero ya DESCIFRADO:");
					nomFichSinCifrado = sc.next();
					aSim.descifrar(tipoCifrado,nomFichKey,nomFichCifrado,nomFichSinCifrado);

				break;
				
				case 4:
					System.out.println("\nIntroduce el nombre del fichero a FIRMAR:");
					nomFichSinFirma = sc.next();
					System.out.println("\nIntroduce el nombre del fichero que contiene la CLAVE PRIVADA:");
					nomFichKs = sc.next();
					System.out.println("\nIntroduce el nombre del fichero donde se ALMACENA LA FIRMA:");
					nomFichFirma = sc.next();
					aSim.firmar(nomFichSinFirma,nomFichKs,nomFichFirma,true);
				break;
				
				case 5: 
					System.out.println("\nIntroduce el nombre del FICHERO EN CLARO que fue firmado:");
					nomFichSinFirma = sc.next();
					System.out.println("\nIntroduce el nombre del FICHERO CON LA FIRMA:");
					nomFichFirma = sc.next();
					System.out.println("\nIntroduce el nombre del fichero con la clave PUBLICA");
					nomFichKp = sc.next();
					aSim.verificarFirma(nomFichKp, nomFichSinFirma, nomFichFirma);
				break;
			}//end switch
		}while(opcion!=0);
	}//end menuAsimetrica
}// end Principal
