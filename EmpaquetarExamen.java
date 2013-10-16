import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.security.KeyFactory;
import java.security.MessageDigest;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.SecureRandom;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.math.BigInteger;
import java.util.Arrays;

public class EmpaquetarExamen {
	public static void main(String[] args) throws Exception {
		if(args.length != 3) {
			System.err.println("[ERROR] Uso del programa: \"EmpaquetarExamen <fichero examen> <clave privada alumno> <clave pública profesor>\"");
			System.exit(1);
		}
		
		Security.addProvider(new BouncyCastleProvider());
		
	// Generar clave secreta AES
	
		SecureRandom rnd = SecureRandom.getInstance("SHA1PRNG");
		Cipher cifrador = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC");	
		int blocksize = cifrador.getBlockSize();
		byte[] ivData = new byte[blocksize];
		rnd.nextBytes(ivData);
		IvParameterSpec ivParam = new IvParameterSpec(ivData);
		KeyGenerator kg = KeyGenerator.getInstance("AES", "BC");
		kg.init(256);
		SecretKey ks = kg.generateKey();
		
	// Cifrar examen con clave secreta
		
		cifrador.init(Cipher.ENCRYPT_MODE, ks, ivParam);
		
		FileInputStream fis = new FileInputStream(args[0]);
		ByteArrayOutputStream baos = new ByteArrayOutputStream();
		byte[] buffer_plano = new byte[1024];
		byte[] buffer_cifrado = new byte[1024];
		int lectura;
		
		byte[] examen = new byte[(int)fis.getChannel().size()];
		fis.read(examen);
		byte[] examen_cifrado = cifrador.doFinal(examen);
	
		fis.close();
		baos.close();
		
	// Cifrar clave secreta con clave publica del profesor
		
		byte[] buffer_ku = new byte[5000];
		fis = new FileInputStream(args[2]);
		fis.read(buffer_ku, 0, buffer_ku.length);
		fis.close();
		
		KeyFactory kf_rsa = KeyFactory.getInstance("RSA", "BC");
		X509EncodedKeySpec x509eks = new X509EncodedKeySpec(buffer_ku);
		PublicKey ku = kf_rsa.generatePublic(x509eks);
		
		cifrador = Cipher.getInstance("RSA", "BC");
		cifrador.init(Cipher.ENCRYPT_MODE, ku);
		
		ByteArrayInputStream bais = new ByteArrayInputStream(ks.getEncoded());
		baos = new ByteArrayOutputStream();
		
		// cifrar ks -> ks_cifrada con ku
		byte[] ks_cifrada = cifrador.doFinal(ks.getEncoded());  
		
		bais.close();
		baos.close();
		
	// Calcular hash de (mensaje cifrado + clave secreta cifrada)
		byte[] ks_plana = ks.getEncoded();
		MessageDigest md = MessageDigest.getInstance("SHA");
		bais = new ByteArrayInputStream(buffer_cifrado);
		md.update(examen_cifrado);
		md.update(ks_cifrada);
		md.update(ivData);
		byte[] hash = md.digest();
	
	// Firmar hash con clave privada del alumno
		
		byte[] buffer_kr = new byte[5000];
		fis = new FileInputStream(args[1]);
		fis.read(buffer_kr, 0, buffer_kr.length);
		fis.close();
		
		PKCS8EncodedKeySpec pkcs8eks = new PKCS8EncodedKeySpec(buffer_kr);
		PrivateKey kr = kf_rsa.generatePrivate(pkcs8eks);
		
		cifrador.init(Cipher.ENCRYPT_MODE, kr);
		
		bais = new ByteArrayInputStream(hash);
		baos = new ByteArrayOutputStream();
		buffer_plano = new byte[1024];
		buffer_cifrado = new byte[1024];
		
		byte[] firma = cifrador.doFinal(hash); 
		
		bais.close();
		baos.close();
		
	// Generar paquete
		
		Paquete pkg = new Paquete();
		pkg.anadirBloque("examen", new Bloque("examen", examen_cifrado));
		pkg.anadirBloque("clave", new Bloque("clave", ks_cifrada));
		pkg.anadirBloque("iv", new Bloque("iv", ivData));
		pkg.anadirBloque("firma", new Bloque("firma", firma));
		
		PaqueteBase64DAO pkg_dao = new PaqueteBase64DAO();
		pkg_dao.escribirPaquete("examen.paquete", pkg);
	}
}
