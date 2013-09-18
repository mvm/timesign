import java.io.*;
import java.security.*;
import java.security.spec.*;
import javax.crypto.*;
import javax.crypto.interfaces.*;
import javax.crypto.spec.*;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

public class Pack {
	public static void main(String[] args)
	{
		if(args.length != 3) {
			System.out.println("Error!");
			return;
		}

		Security.addProvider(new BouncyCastleProvider());
		Cipher aes;
		KeyGenerator aesKeyGen;
		Key aesKey;
		try {
			aes = Cipher.getInstance("AES/CTR/PKCS5Padding", "BC"); 
			aesKeyGen = KeyGenerator.getInstance("AES", "BC");
		} catch(Exception e) {
			System.out.println(e.toString());
			return;
		}

		// Generate key
		aesKeyGen.init(256);
		aesKey = aesKeyGen.generateKey();

		// Generate random IV
		byte iv[] = new byte[16];
		SecureRandom rand = new SecureRandom();
		rand.nextBytes(iv);
	}
}
