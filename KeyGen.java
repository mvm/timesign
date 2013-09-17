import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class KeyGen {
	public static void main(String[] args)
	{
		if(args.length != 1) {
			System.out.println("Error!");
			return;
		}

		Security.addProvider(new BouncyCastleProvider());
		KeyPairGenerator pg;
		KeyFactory keyFactoryRSA;
		try {
			pg = KeyPairGenerator.getInstance("RSA", "BC");
			keyFactoryRSA = KeyFactory.getInstance("RSA", "BC");
		} catch(NoSuchAlgorithmException e) {
			System.out.println("RSA algorithm not found");
			return;
		} catch(NoSuchProviderException e) {
			System.out.println("BouncyCastle not found");
			return;
		}

		pg.initialize(4096);
		KeyPair kp = pg.generateKeyPair();
		PrivateKey private_key = kp.getPrivate();
		PublicKey public_key = kp.getPublic();
		PKCS8EncodedKeySpec pkcs8Spec = new PKCS8EncodedKeySpec(private_key.getEncoded());

		try {
			FileOutputStream out = new FileOutputStream(args[0] + ".prv");
			out.write(pkcs8Spec.getEncoded());
			out.close();
		} catch(Exception e) {
			System.out.println(e.toString());
			return;
		}

		X509EncodedKeySpec x509Spec = new X509EncodedKeySpec(public_key.getEncoded());
		
		try {
			FileOutputStream out = new FileOutputStream(args[0] + ".pub");
			out.write(x509Spec.getEncoded());
			out.close(); 
		} catch(Exception e) {
			System.out.println(e.toString());
			return;
		}
	}
}
