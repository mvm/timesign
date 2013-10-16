import java.io.FileOutputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Security;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class GenerarClaves {
	public static void main(String[] args) throws Exception {
		if(args.length != 1) {
			System.err.println("[ERROR] Uso del programa: \"GenerarClaves <identificador>\"");
			System.exit(1);
		}
		
		Security.addProvider(new BouncyCastleProvider());
		
		// Generar par de claves RSA
		
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA", "BC");
		kpg.initialize(4096);
		KeyPair kp = kpg.generateKeyPair();
		PublicKey ku = kp.getPublic();
		PrivateKey kr = kp.getPrivate();
		
		// Guardar clave publica RSA en fichero
		
		X509EncodedKeySpec x509eks = new X509EncodedKeySpec(ku.getEncoded());
		FileOutputStream fos = new FileOutputStream(args[0] + ".publica");
		fos.write(x509eks.getEncoded());
		fos.close();
		
		// Guardar clave privada RSA en fichero
		
		PKCS8EncodedKeySpec pkcs8eks = new PKCS8EncodedKeySpec(kr.getEncoded());
		fos = new FileOutputStream(args[0] + ".privada");
		fos.write(pkcs8eks.getEncoded());
		fos.close();
		
		System.out.println("Generadas claves RSA pública y privada de 4096 bits en ficheros " + args[0] + ".publica" + " y " + args[0] + ".privada");
	}
}