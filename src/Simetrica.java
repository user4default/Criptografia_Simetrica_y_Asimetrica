import java.io.BufferedInputStream;
import java.io.BufferedOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.SecureRandom;

import org.bouncycastle.crypto.CipherKeyGenerator;
import org.bouncycastle.crypto.DataLengthException;
import org.bouncycastle.crypto.InvalidCipherTextException;
import org.bouncycastle.crypto.KeyGenerationParameters;
import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PKCS7Padding;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.util.encoders.Hex;

public class Simetrica {

	public Simetrica() {
	}//end Simetrica 
	public void generarClave(String nomFich) throws IOException {
		
		byte[] key = new byte[256]; // El TAMAÑO de la CLAVE es de 256 bits

		BufferedOutputStream fichBin = new BufferedOutputStream(new FileOutputStream(nomFich)); // Abrimos un buffer para sacar al fichero la salida generada con las CLAVES
		CipherKeyGenerator keyGen = new CipherKeyGenerator(); 
		keyGen.init(new KeyGenerationParameters(new SecureRandom(),256)); // Inicializamos el generador de claves, que recibe como PARAMETRO el TAMAÑO DE CLAVE
		key = keyGen.generateKey(); // Generamos la clave
		
		// ESCRIBIMOS la CLAVE SECRETA generada en el fichero de salida
		fichBin.write(Hex.encode(key));
		fichBin.close(); // IMPORTANTE CERRAR EL BUFFER
	}//end generarClave
	
	public void cifrar(String NomFichKey, String NomFichNoCifrado, String NomFichCifrado) throws IOException {
		
		BufferedInputStream ficheroKey = new  BufferedInputStream(new FileInputStream(NomFichKey)); // Creamos un buffer para el FICHERO de ENTRADA con la CLAVE SECRETA
		byte[] arrayKey = new byte[32]; // Al estar la CLAVE en HEXADECIMAL y tener un TAMAÑO de 256 bits, el ARRAY donde guardamos la CALVE leida  ha de ser de 32 POSICIONES
		ficheroKey.read(arrayKey);// Leemos del fichero 
		KeyParameter kp = new KeyParameter(Hex.decode(arrayKey)); // A partir de la CLAVE del fichero, CRREAMOS el PARAMETRO kp (CLAVE SECRETA) para el CIFRADOR
		ficheroKey.close();

		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()),new PKCS7Padding()); // Instanciamos el CIFRADOR con sus PARAMETROS -> CBC(ALGORITMO,PADDING)
		cifrador.init(true,kp); // Inicializamos el cifrador (true = cifrado)
		
		FileInputStream fichClaro = new FileInputStream(NomFichNoCifrado);
		BufferedInputStream fClaro = new BufferedInputStream(fichClaro);
		FileOutputStream fichCifrado = new FileOutputStream(NomFichCifrado);
		BufferedOutputStream ficheroCifrado = new BufferedOutputStream(fichCifrado);
		
		int maxOutputSize = cifrador.getOutputSize(fClaro.available()); // GETOUTPUSIZE nos da un tamaño maximo en funcion del tamaño del fichero de entrada
		byte BloqClaro[] = new byte [cifrador.getBlockSize()]; // El ARRAY ha de tener un TAMAÑO MAXIMO DETERMINADO por el TAMAÑO del BLOQUE que permite el algoritmo
		byte arrayCifrado[] = new byte [maxOutputSize];

		int bytes_leidos = 0,
				bytes_cifrados = 0;
		
		bytes_leidos = fClaro.read(BloqClaro); // Realizamos la lectura del 1er bloque de bytes, en la variable BYTES_LEIDOS almacena el nº de bloques leido o -1 si es el final del fichero
		while(bytes_leidos != -1){ // Mientras no sea el final del fichero . . . 
			bytes_cifrados += cifrador.processBytes(BloqClaro,0,bytes_leidos,arrayCifrado,bytes_cifrados); // Procesa el bloque arrayBloqClaro desde la posicion 0 hasta el ULTIMO BYTE Q HA LEIDO (bytes_leidos) 
			bytes_leidos = fClaro.read(BloqClaro);														  // COPIA en el array arrayCifrado los bytes cifrados en la 1ª posicion libre (bytes_cifrados)
		}//end while
		fClaro.close();
		try {
			cifrador.doFinal(arrayCifrado,bytes_cifrados); // La funcion DOFINAL hace el procesado final del CIFRADO
		} catch (DataLengthException | IllegalStateException
				| InvalidCipherTextException e) {
			e.printStackTrace();
		}//end catch
		ficheroCifrado.write(arrayCifrado); // ESCRIBIMOS el resultado en el fichero de salida
		ficheroCifrado.close();			
	}//end cifrar
	
	public void descifrar(String NomFichKey, String NomFichCifrado, String NomFichNoCifrado) throws IOException {
		
		BufferedInputStream ficheroKey = new  BufferedInputStream(new FileInputStream(NomFichKey)); // Creamos un buffer para el fichero con la clave
		byte[] arrayKey = new byte[32]; // Al estar la CLAVE en HEXADECIMAL y tener un TAMAÑO de 256 bits, el ARRAY donde guardamos la CALVE leida  ha de ser de 32 POSICIONES
		ficheroKey.read(arrayKey);// Leemos del fichero 
		KeyParameter kp = new KeyParameter(Hex.decode(arrayKey)); // A partir de la clave del fichero, creamos el parametro de la clave para el cifrador
		ficheroKey.close();

		PaddedBufferedBlockCipher cifrador = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()),new PKCS7Padding()); // A partir de la CLAVE del fichero, CRREAMOS el PARAMETRO kp (CLAVE SECRETA) para el CIFRADOR
		cifrador.init(false,kp); // Inicializamos el cifrador (false = descifrado)
		
		FileOutputStream fichClaro = new FileOutputStream(NomFichNoCifrado);
		BufferedOutputStream fClaro = new BufferedOutputStream(fichClaro);
				
		FileInputStream fichCifrado = new FileInputStream(NomFichCifrado);
		BufferedInputStream fCifrado = new BufferedInputStream(fichCifrado);
		
		int maxOutputSize = cifrador.getOutputSize(fCifrado.available());
		byte BloqCifrado[] = new byte [cifrador.getBlockSize()]; // El array ha de tener un tamaño maximo determinado por el tamaño maximo de bloque que permite el algoritmo
		byte arrayClaro[] = new byte [maxOutputSize];

		int bytes_leidos = 0,
				bytes_descifrados = 0;
		
		bytes_leidos = fCifrado.read(BloqCifrado); // Realizamos la lectura del 1er bloque de bytes, en la variable almacena el nº de bloques leido o -1 si es el final del fichero
		while(bytes_leidos != -1){ // Mientras no sea el final del fichero . . . 
			bytes_descifrados += cifrador.processBytes(BloqCifrado,0,bytes_leidos,arrayClaro,bytes_descifrados); // Procesa el bloque BloqCifrado desde la posicion 0 hasta el ULTIMO BYTE Q HA LEIDO (bytes_leidos) 
			bytes_leidos = fCifrado.read(BloqCifrado);														    // COPIA en el array arrayClaro los bytes cifrados en la 1ª posicion libre (bytes_descifrados)
		}//end while
		fCifrado.close();
		try {
			cifrador.doFinal(arrayClaro,bytes_descifrados);// La funcion DOFINAL hace el procesado final del DESCIFRADO
		} catch (DataLengthException | IllegalStateException
				| InvalidCipherTextException e) {
			e.printStackTrace();
		}//end catch
		fClaro.write(arrayClaro); // ESCRIBIMOS el resultado en el fichero correspondiente para el descifrado
		fClaro.close();			
	}//end descifrar
}//end SIMETRICA
