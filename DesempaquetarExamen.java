import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import java.security.MessageDigest;
import javax.crypto.spec.SecretKeySpec;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.util.Arrays;
import java.util.Date;

public class DesempaquetarExamen {
	public static void main(String[] args) throws Exception {
		if(args.length != 4) {
			System.err.println("[ERROR] Uso del programa: \"DesmpaquetarExamen <paquete examen> <clave privada profesor> <clave publica alumno> <clave publica TSAuth>\"");
			System.exit(1);
		}
		
		Security.addProvider(new BouncyCastleProvider());
		
	// Extraer bloques del paquete
		
		Paquete pkg = new PaqueteBase64DAO().leerPaquete("examen.paquete");
		byte[] examen_cifrado = pkg.getBloque("examen").getContenido();
		byte[] ks_cifrada = pkg.getBloque("clave").getContenido();
		byte[] firma = pkg.getBloque("firma").getContenido();
		byte[] ivData = pkg.getBloque("iv").getContenido();
		byte[] timestamp = pkg.getBloque("timestamp").getContenido();
		
	// Descifrar clave secreta con clave privada del profesor
		
		byte[] buffer_kr = new byte[5000];
		FileInputStream fis = new FileInputStream(args[1]);
		fis.read(buffer_kr, 0, buffer_kr.length);
		fis.close();
		
		KeyFactory kf = KeyFactory.getInstance("RSA", "BC");
		PKCS8EncodedKeySpec pkcs8eks = new PKCS8EncodedKeySpec(buffer_kr);
		PrivateKey kr = kf.generatePrivate(pkcs8eks);
		
		Cipher cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.DECRYPT_MODE, kr);
		
		ByteArrayInputStream bais = new ByteArrayInputStream(ks_cifrada);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer_cifrado = new byte[1000];
		byte[] buffer_plano;
		int lectura;
		
		byte[] buffer_ks = cifrador.doFinal(ks_cifrada); 
		
	// Descifrar examen con clave secreta
		SecretKeySpec ks_spec = new SecretKeySpec(buffer_ks, "AES");
		IvParameterSpec ivParam = new IvParameterSpec(ivData);
		
		cifrador = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");
		cifrador.init(Cipher.DECRYPT_MODE, ks_spec, ivParam);
		
		byte[] examen = cifrador.doFinal(examen_cifrado); 
		
		fis.close();
		baos.close();
		
	// Comprobar que el paquete va firmado por el alumno
		// Computar sha(examen_cifrado || ks_cifrada || IV)
		MessageDigest md = MessageDigest.getInstance("SHA");
		md.update(examen_cifrado);
		md.update(ks_cifrada);
		md.update(ivData);
		byte[] hash_computada = md.digest();

		// Comparar con el firmado con la clave privada del alumno
		byte[] buffer_alumno_ku;
		File alumno_ku_fd = new File(args[2]);
		buffer_alumno_ku = new byte[(int) alumno_ku_fd.length()];
		FileInputStream alumno_ku_fis = new FileInputStream(alumno_ku_fd);
		alumno_ku_fis.read(buffer_alumno_ku, 0, buffer_alumno_ku.length);
		alumno_ku_fis.close();
		PublicKey alumno_ku = kf.generatePublic(new X509EncodedKeySpec(buffer_alumno_ku));
		
		Cipher cipher_rsa = Cipher.getInstance("RSA", "BC");
		cipher_rsa.init(Cipher.DECRYPT_MODE, alumno_ku);

		byte[] firma_plain = cipher_rsa.doFinal(firma);

		// Comparar los dos hash
		if(!Arrays.equals(hash_computada, firma_plain)) {
			System.out.println("[ERROR] La firma no cuadra!");
			return;
		} else {
			System.out.println("Firma correcta (" + args[2] + ")");
		}

	// Comprobar timestamp
		// Comparar con el firmado con la clave privada del alumno
		byte[] buffer_auth_ku;
		File auth_ku_fd = new File(args[3]);
		buffer_auth_ku = new byte[(int) auth_ku_fd.length()];
		FileInputStream auth_ku_fis = new FileInputStream(auth_ku_fd);
		auth_ku_fis.read(buffer_auth_ku, 0, buffer_auth_ku.length);
		auth_ku_fis.close();
		PublicKey auth_ku = kf.generatePublic(new X509EncodedKeySpec(buffer_auth_ku));
		
		cipher_rsa.init(Cipher.DECRYPT_MODE, auth_ku);

		byte[] timestamp_plain = cipher_rsa.doFinal(timestamp);

		BigInteger time = new BigInteger(timestamp_plain);
		Date sign_date = new Date(time.longValue());
		System.out.println("Firmado el " + sign_date);
	// Generar examen
		
		bais = new ByteArrayInputStream(examen);
		FileOutputStream fos = new FileOutputStream("examen.txt");
		
		while((lectura = bais.read()) != -1) {
			fos.write(lectura);
		}
		
		bais.close();
		fos.close();
	}
}
