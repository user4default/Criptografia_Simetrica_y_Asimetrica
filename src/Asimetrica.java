import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.BufferedReader;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.SecureRandom;

import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.Digest;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.digests.SHA3Digest;
import org.bouncycastle.crypto.encodings.PKCS1Encoding;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.util.encoders.Hex;

public class Asimetrica {

	public Asimetrica() {
	}// end Asimetrica
	
	public void generarClaves(String nomFichKs, String nomFichKp) throws IOException {

		GuardarFormatoPEM g =  new GuardarFormatoPEM(); // Instanciamos un objeto GUARDAR FORMATO para crear ficheros con las CLAVES en formato de representacion X.509
		PrintWriter fPrivada = new PrintWriter(new FileWriter(nomFichKs));
		PrintWriter fPublica = new PrintWriter(new FileWriter(nomFichKp));

		AsymmetricCipherKeyPair claves; // Aqui guardamos las claves generadas
		RSAKeyParameters  Ks ; // Clave PUBLICA
		RSAKeyParameters Kp; // Clave PRIVADA
		
		RSAKeyGenerationParameters parametros = new RSAKeyGenerationParameters(BigInteger.valueOf(3),new SecureRandom(),2048,10);// Instanciamos el generador de claves con sus correspondientes parametros
		RSAKeyPairGenerator generadorClaves = new RSAKeyPairGenerator(); 	// MODULO 3 , NUM RAND , TAMAÑO CLAVE, CARDINAL EULER
		generadorClaves.init(parametros); // Inicializamos el genrador de claves 
		claves = generadorClaves.generateKeyPair(); // Guardamos en CLAVES, la pareja de claves genrada
		Ks = (RSAKeyParameters) claves.getPrivate(); // Guardamos la CLAVE PRIVADA en KS
		Kp = (RSAKeyParameters) claves.getPublic(); // Guardamos la CLAVE PUBLICA en KP
		
		fPrivada.println(new String(Hex.encode(Ks.getModulus().toByteArray()))); // PRINT LINE!! = \n
		fPrivada.print(new String(Hex.encode(Ks.getExponent().toByteArray()))); // PRINT A SECAS !! = no  \n
		  																			// GUARDAMOS LAS CLAVES EN FORMATO HEXADECIMAL EN LOS CORRESPONDIENTES FICHEROS
		fPublica.println(new String(Hex.encode(Kp.getModulus().toByteArray())));
		fPublica.print(new String(Hex.encode(Kp.getExponent().toByteArray())));
		
		g.guardarClavesPEM(Kp, Ks); // GUARDAMOS LAS CLAVES CON FORMATO DE REPRESENTACION X.509
		
		fPublica.close();
		fPrivada.close();
	}//end generar claves
	
	public void cifrar(String nomFichNcif, String clave, String nomFichCif, String tipo) throws IOException, InvalidCipherTextException{
		
		BufferedReader KeyReader = new BufferedReader(new FileReader(clave)); // Buffer especial para las claves 
		
		BigInteger modulo = new BigInteger(Hex.decode(KeyReader.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(KeyReader.readLine()));
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equalsIgnoreCase("privada"),modulo,exponente); // Instanciamos los parametros Correspondientes para el algoritmo que usamos (RSA)
		
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine()); // Instanciamos el cifrador
		cifrador.init(true,parametros); // Inicializamos el cifrador (true = cifrado)

		BufferedInputStream fClaro = new BufferedInputStream(new FileInputStream(nomFichNcif));
		BufferedOutputStream fCifrado = new BufferedOutputStream(new FileOutputStream(nomFichCif));
		
		byte BloqClaro[] = new byte [cifrador.getInputBlockSize()]; // El array ha de tener un tamaño maximo determinado por el tamaño maximo de bloque que permite el algoritmo
		int bytes_leidos = 0;
		
		bytes_leidos = fClaro.read(BloqClaro);// Realizamos la lectura del 1er bloque de bytes, en la variable BYTES_LEIDOS almacena el nº de bloques leido o -1 si es el final del fichero
		while(bytes_leidos != -1){
				fCifrado.write(cifrador.processBlock(BloqClaro,0,bytes_leidos)); // Segun vamos cifradno con la funcion ProcessBlock(BLOQUE SIN CIFRAR, DESPLAZ. ENTRADA, BYTES QUE VAMOS LEYENDO) LO ESCRIBIMOS en el fichero de salida
				bytes_leidos = fClaro.read(BloqClaro);
		}//end while
		fCifrado.close();
		fClaro.close();
		KeyReader.close();
	}//end cifrar
	
	public void descifrar(String tipo,String clave,String nomFichCif,String nomFichNcif) throws IOException, InvalidCipherTextException{
		
		BufferedReader KeyReader = new BufferedReader(new FileReader(clave)); // Buffer especial para las claves 
		
		BigInteger modulo = new BigInteger(Hex.decode(KeyReader.readLine()));
		BigInteger exponente = new BigInteger(Hex.decode(KeyReader.readLine()));
		RSAKeyParameters parametros = new RSAKeyParameters(tipo.equalsIgnoreCase("privada"),modulo,exponente);
		
		AsymmetricBlockCipher cifrador = new PKCS1Encoding(new RSAEngine());
		cifrador.init(false,parametros); // Inicializamos el cifrador (false = descifrado)
		
		BufferedOutputStream fClaro = new BufferedOutputStream(new FileOutputStream(nomFichNcif));
		BufferedInputStream fCifrado = new BufferedInputStream(new FileInputStream(nomFichCif));
		
		byte arrayCifrado[] = new byte [cifrador.getInputBlockSize()];
		int bytes_leidos = 0;
		
		bytes_leidos = fCifrado.read(arrayCifrado);
		while(bytes_leidos != -1){
			fClaro.write(cifrador.processBlock(arrayCifrado,0,bytes_leidos)); // Segun vamos descifradno con la funcion ProcessBlock(BLOQUE CIFRADO, DESPLAZ. ENTRADA, BYTES QUE VAMOS LEYENDO) LO ESCRIBIMOS en el fichero de salida
			bytes_leidos = fCifrado.read(arrayCifrado);
		}//end while
		fCifrado.close();
		fClaro.close();
		KeyReader.close();
	}// end descifrar
	
	public void firmar(String nomFichNfirm,String nomFichKey,String nomFichFirm, boolean cifrar) throws IOException, InvalidCipherTextException{
		Digest resumen = new SHA3Digest(); // Instanciamos el generados hash
		byte arrayNofirmado[] = new byte [resumen.getDigestSize()]; 
		byte arrayFirmado[] = new byte [resumen.getDigestSize()];
		
		BufferedOutputStream fFirm = new BufferedOutputStream(new FileOutputStream("No_Cifrado_".concat(nomFichFirm)));
		BufferedInputStream fNFirm = new BufferedInputStream(new FileInputStream(nomFichNfirm));
		
		int leidos = 0;
		
		leidos = fNFirm.read(arrayNofirmado); // Vamos leyendo del fichero 
		while(leidos != -1){
				resumen.update(arrayNofirmado,0,leidos); // Segun vamos leyendo calculamos el hash correspondiente a los bytes de entrada, y asi hasta el ultimo bloque 
				leidos = fNFirm.read(arrayNofirmado);
		}//end while
		resumen.doFinal(arrayFirmado,0); // Hacemos el procesado final 
		fFirm.write(arrayFirmado); // Escribimos en el fichero el resultado de firmar el fichero 
		fFirm.close();
		fNFirm.close();
		if(cifrar){ // En caso de no estar en el proceso de firma el valor de CIFRAR SERIA FALSE y pues no cifraria ( LO USAMOS EN VERIFICAR FIRMA)
			cifrar("No_Cifrado_".concat(nomFichFirm),nomFichKey,nomFichFirm,"privada"); // GUARDA LA FIRMA CIFRADA CON LA CLAVE PRIVADA DEL USUARIO
		}

	}// end FIRMAR
	
	public void verificarFirma(String nomFichPublicKey,String nomFichClaro,String nomFichFirma) throws InvalidCipherTextException, IOException{
		boolean iguales = true;
		descifrar("publica",nomFichPublicKey,nomFichFirma,"Firma_en_claro_".concat(nomFichFirma)); // DESCIFRAMOS LA FIRMA CON LA CLAVE PUBLICA DEL USUARIO FIRMANTE QUE PREVIAMENTE TENEMOS QUE TENER ( JUNTO CON EL FICHERO DEL MENSAJE EN CLARO Y EL DEL FIRMADO)
		firmar(nomFichClaro,nomFichPublicKey,"Comp_Firma_".concat(nomFichFirma),false); // FIRMAMOS (CALCULAMOS EL HASH) DEL MENSAJE EN CLARO DEL QUE SE HA ENVIDADO LA FIRMA CON LA CLAVE PUBLICA DEL USUARIO FIRMANTE
		
		BufferedReader FirmaEnviada = new BufferedReader(new FileReader("Firma_en_claro_".concat(nomFichFirma)));
		BufferedReader FirmaCalculada = new BufferedReader(new FileReader("No_Cifrado_Comp_Firma_".concat(nomFichFirma)));
		
		while(FirmaEnviada.read()!=-1 && FirmaCalculada.read()!=-1 && iguales!=false) { // COMPARAMOS BYTE A BYTE LAS DOS FIRMAS Y SI SON IGUALES PODEMOS ESTAR SEGUROS DE QUE EL MENSAJE ES DE LA ENTIDAD FIRMANTE Y NO HA SUFRIDO MODIFICACIONES (AUTENTICACION E INTEGRIDAD)
			if(FirmaEnviada.read()!= FirmaCalculada.read()) {
				iguales = false;
			}// end if 
		}// end while

		FirmaEnviada.close();
		FirmaCalculada.close();
		if(iguales){
			System.out.println("\nSon Iguales =) ");
		}else{
			System.out.println("\nNo son Iguales =( ");
		}// end else
	}// end VERIFICARFIRMA
	
}// Asimetrica
