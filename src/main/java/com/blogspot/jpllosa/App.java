package com.blogspot.jpllosa;

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

import org.apache.commons.codec.binary.Base64;

import static org.junit.Assert.*;

public class App {

	private CryptographyKeyReader ckReader;
	private Cipher cipher;
	
	PublicKey publicKey;
    PrivateKey privateKey;
    
    KeyPair keyPair;

	public App() {
		ckReader = new CryptographyKeyReader();
		try {
        	cipher = Cipher.getInstance("RSA");
        } catch (NoSuchAlgorithmException | NoSuchPaddingException e) {
        	e.printStackTrace();
        }

		//privateKey = getPrivateKey("my-private-key.pem", "");
//		$ openssl genrsa -out my-private-key.pem 4096
//		Generating RSA private key, 4096 bit long modulus
//		........................................................++
//		....++
//		e is 65537 (0x10001)

		//publicKey = getPublicKey("my-public-key.pem");
//        $ openssl rsa -in my-private-key.pem -outform PEM -pubout -out my-public-key.pem
//        writing RSA key
		
		privateKey = getPrivateKey("mypassword-private-key.pem", "mypassword");
//		$ openssl genrsa -out mypassword-private-key.pem 4096 -passout pass:mypassword
//		Generating RSA private key, 4096 bit long modulus
//		.........................................................................................................++
//		....................++
//		e is 65537 (0x10001)
        
		publicKey = getPublicKey("mypassword-public-key.pem");
//		$ openssl rsa -in mypassword-private-key.pem -outform PEM -pubout -out mypassword-public-key.pem
//		writing RSA key
        
        keyPair = new KeyPair(publicKey, privateKey);
	}
    
    public String encrypt(String data) {
    	try {
    		cipher.init(Cipher.ENCRYPT_MODE, keyPair.getPublic());
    		return Base64.encodeBase64String(cipher.doFinal(data.getBytes(StandardCharsets.UTF_8)));
    	} catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
    		System.out.println("Cannot encrypt data");
    		return "";
    	}
    }
    
    public String decrypt(String data) {
    	try {
    		cipher.init(Cipher.DECRYPT_MODE, keyPair.getPrivate());
    		return new String(cipher.doFinal(Base64.decodeBase64(data)), StandardCharsets.UTF_8);
    	} catch (BadPaddingException | IllegalBlockSizeException | InvalidKeyException e) {
    		System.out.println("Cannot decrypt data");
    		return "";
    	}
    }
    
    private PublicKey getPublicKey(String filename) {
    	PublicKey key = null;
    	
    	try {
    		byte[] keyBytes = ckReader.readPublicKey(filename);
    		X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes); // Represents ASN.1 encoding of a public key
    		KeyFactory keyFactory = KeyFactory.getInstance("RSA");
    		key = keyFactory.generatePublic(spec);
    	} catch (NullPointerException npe) {
    		System.out.println("Cannot read public key from file.");
    	} catch (NoSuchAlgorithmException | InvalidKeySpecException e) {
    		System.out.println("Cannot create public key instance from file.");
    	}
    	
    	return key;
    }
    
    private PrivateKey getPrivateKey(String filename, String password) {
    	PrivateKey key = null;
    	
    	try {
    		byte[] keyBytes = ckReader.readPrivateKey(filename, password);
    		PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes); // Represents ASN.1 encoding of a private key
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            key = keyFactory.generatePrivate(spec);
    	} catch (NullPointerException fileE) {
    		System.out.println("Cannot read private key from file.");
        } catch (NoSuchAlgorithmException | InvalidKeySpecException cryptoE) {
        	System.out.println("Cannot create private key instance from file.");
        }
        return key;
    }
    
    public static void main(String[] args) {
        System.out.println( "Encrypt/Decrypt with Public/Private keys." );

        App app = new App();

        // private/public key no password
//        String encryptedString = app.encrypt("hello world!");
//        System.out.println("Encrypted: " + encryptedString);
//        
//        String decryptedString = app.decrypt("BfT1vYxgoJVYy0RPNkzriRHpkYLXVmsIXMHVjh3SfAOLHga79Wqafq2Hhbzc4JK5gxUOgMbS2n4o5Uzi7N3LjcXGVHzKPwaMJVp7ToSNWCmSNmEV7TqxyKydFr8srnybfRrKM4i+hzAs9HEULKr1RSV3OVt8fq7LtrXa0OldbFvkFKzXgmupxYzUzwmuFPhed+s2H7b+iB3QAxBmsmYa5LC+5qo4aOXQvhWHNqhDQ8+HHuJ+nsECO1Q7w1ET5VpST/RDljCgY14CHeQvuqVCMc0Tl3ueOiMgPvDxp5GT4HTb46VxHWLJTvHTC4NboF2vXrB3XgwB8tSfzrHHrV601n0f7anG8lJfbo5Fm7ow+JqRufInmPawzwHSoKxBQLFiYQRopddeSfuXhnpz+Cg1ZGBzdf7OM5v9fTmJaqv/UaVlyqyq1bGWzg8zmAUXiVibB1ri/hwL2mxGM2st+2uFiCCf0ehEaQuP4Jy8vmFcvLLz10JhMFd31fnq+yd3E1Iaon4bcyVeayge2xHD5RyAIn7akDRawPysBspWYmEc3DS1jlvfuXgV81QRy3loGlgdSO7yoEzgOvWgbDx/iYhUa6OA2p0c7B5y6WqzCY8XPKHNl8uR1Svhh8FT2VGnlcVOJqIKQdDjv9VacZtLt/n8HnbHzXX41lSt/hEICZnJPJE=");
//        System.out.println("Decrypted: " + decryptedString);
        
        // private/public key with password
//        String encryptedString = app.encrypt("hello world with password!");
//        System.out.println("Encrypted: " + encryptedString);
//        
//        String decryptedString = app.decrypt("ZDjeXMmUIIZ+TC8UiKLgv6x9bO1jAxx0ATUkrwhp+gLksotBtwTehg6Q+PxxOuABpGJ8IdwizF/vKPHNNZmW9o/zCTCrrneTN5cbbeN9yocfltESx5DIJuzvt4el0aQ6dpUIWMYN6hD1spKmjqPKcf7RzzjBIOha7ErMVxLEnsUdxEe1wRMiq2839mEg4nASzmZQa/TkVayVrgmfNgWjqnae8Pw2BGJ0Yp/YC2MeEaOwqhmEsyVmQ5fRUu/BO8UzevJMxO74pxscKQQoMjLk5Kn8zW4j0l7ilpUuI3yVvTmOoCrlA/EaIdzrNaygsaExEvu8aRgboUoYpa4UqoSkk9H/BFzlPWCUKCTEmoJesaP9+wFmJOOeW/MTD3StiIE+plxwMadWyLd/Aw74j+fHi8SnbJ0lhiUKYMu1nH62jhxbP/bb4kDOHz8R2fxVIlNaNyfvSZrObJE9SgU+Hl+dGyy86mXN0YEuTinNdwcpH6wMj+Vt5WB22UrVz4zev5C/uCjjaHnZzUw6o6+9FlbLkfPxu8mGgX9xbWyy6kjD3bG7MxA7GSSoKLzJZkfZML8FrcLn3sA6T74ZxouUB0Cc7jDIF9b3QS/QMwI7ob+bt8BfvaKib8/g73dq2dpugvRURjHxHttha0pDPXKO1VggOZgy6wouwZAMDj6aKsXrL/A=");
//        System.out.println("Decrypted: " + decryptedString);
        
        String encryptedString = app.encrypt("once more unto the breach...");
        System.out.println("Encrypted: " + encryptedString);
        
        String decryptedString = app.decrypt(encryptedString);
        System.out.println("Decrypted: " + decryptedString);
        assertEquals("once more unto the breach...", decryptedString);
    }
}
