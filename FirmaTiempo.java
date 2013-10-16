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

public class FirmaTiempo {
	public static void main(String[] args) throws Exception {
		if(args.length != 1) {
			System.err.println("[ERROR] Uso del programa: \"FirmaTiempo <clave privada autoridad>\"");
			System.exit(1);
		}
		
		Security.addProvider(new BouncyCastleProvider());
		
	// Extraer bloques del paquete
		
		PaqueteBase64DAO pkg_dao = new PaqueteBase64DAO();
		Paquete pkg = pkg_dao.leerPaquete("examen.paquete");

		// Conseguir tiempo
		BigInteger time;
		Date current = new Date();
		time = BigInteger.valueOf(current.getTime());

		// Leer clave privada
		File auth_pk_f = new File(args[0]);
		FileInputStream auth_pk_fis = new FileInputStream(auth_pk_f);
		byte[] buffer_pk = new byte[(int) auth_pk_f.length()];
		auth_pk_fis.read(buffer_pk, 0, buffer_pk.length);
		auth_pk_fis.close();

		// Encriptar hash	
		Cipher cipher_rsa = Cipher.getInstance("RSA", "BC");
		KeyFactory key_fac = KeyFactory.getInstance("RSA", "BC");
		PrivateKey auth_pk = key_fac.generatePrivate(new PKCS8EncodedKeySpec(buffer_pk));

		cipher_rsa.init(Cipher.ENCRYPT_MODE, auth_pk);
		byte[] timestamp_crypt = cipher_rsa.doFinal(time.toByteArray());

		// Escribir datos
		pkg.anadirBloque("timestamp", new Bloque("timestamp", timestamp_crypt));
		pkg_dao.escribirPaquete("examen.paquete", pkg);
		
		System.out.println("Firmado el " + current);
	}
}
