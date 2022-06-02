package com.blogspot.jpllosa;

import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.security.Security;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;
import org.bouncycastle.util.io.pem.PemObject;

public class CryptographyKeyReader {

	public CryptographyKeyReader() {
		Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
	}
	
	public byte[] readPublicKey(String filename) {
		try (PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(filename)))) {
			PemObject keyContent = pemParser.readPemObject();
			return keyContent.getContent();
		} catch (NullPointerException | IOException e) {
			System.out.println("Cannot read public key PEM format from file.");
			return null;
		}
	}
	
	public byte[] readPrivateKey(String filename, String password) {
		try (PEMParser pemParser = new PEMParser(new InputStreamReader(new FileInputStream(filename)))) {
			Object keyPair = pemParser.readObject();
			PrivateKeyInfo keyInfo;
			if (keyPair instanceof PEMEncryptedKeyPair) {
				PEMDecryptorProvider decryptorProvider = new JcePEMDecryptorProviderBuilder().build(password.toCharArray());
				PEMKeyPair decryptedKeyPair = ((PEMEncryptedKeyPair) keyPair).decryptKeyPair(decryptorProvider);
				keyInfo = decryptedKeyPair.getPrivateKeyInfo();
			} else {
				keyInfo = ((PEMKeyPair) keyPair).getPrivateKeyInfo();
			}
			
			return keyInfo.getEncoded();
		} catch (NullPointerException | IOException e) {
			System.out.println("Cannot read private key PEM format from file.");
			return null;
		}
	}
}
