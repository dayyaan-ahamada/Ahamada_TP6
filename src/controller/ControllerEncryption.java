package controller;

import model.EncryptedMessage;

import java.security.Key;
import java.security.KeyFactory;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.KeyGenerator;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

public class ControllerEncryption {

	private static final int KEY_GEN_DES_BYTE = 56;
	private static final int KEY_GEN_RSA_BYTE = 1024;
	private static final String CIPHER_DES_MODE = "DES/ECB/PKCS5Padding";
	private static final String CIPHER_RSA_MODE = "RSA";

	private static final String KEY_GEN_DES_MODE = "DES";
	private static final String KEY_GEN_RSA_MODE = "RSA";

	public static SecretKey getDESKey() {
		KeyGenerator keyGenerator;
		try {
			keyGenerator = KeyGenerator.getInstance(KEY_GEN_DES_MODE);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		keyGenerator.init(KEY_GEN_DES_BYTE);
		return keyGenerator.generateKey();
	}
	
	public static SecretKey getDESKeyFromByteArray(byte[] byteKeyDES) {
		return new SecretKeySpec(byteKeyDES, KEY_GEN_DES_MODE);
	}
	
	public static PublicKey getRSAKeyFromByteArray(byte[] byteKeyRSA) {
		try {
			return KeyFactory.getInstance(KEY_GEN_RSA_MODE).generatePublic(new X509EncodedKeySpec(byteKeyRSA));
		} catch (InvalidKeySpecException | NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
	}

	public static KeyPair getRSAKeys() {
		KeyPairGenerator keyPairGenerator;
		try {
			keyPairGenerator = KeyPairGenerator.getInstance(KEY_GEN_RSA_MODE);
		} catch (NoSuchAlgorithmException e) {
			e.printStackTrace();
			return null;
		}
		keyPairGenerator.initialize(KEY_GEN_RSA_BYTE);
		return keyPairGenerator.genKeyPair();
	}

	private static byte[] cryptDES(byte[] message, int mode, Key keyDES, String cypherMode) {
		Cipher cipher;
		byte[] newMessage;
		try {
			cipher = Cipher.getInstance(cypherMode);
			cipher.init(mode, keyDES);
			newMessage = cipher.doFinal(message);
		} catch (NoSuchAlgorithmException | NoSuchPaddingException |
				InvalidKeyException | IllegalBlockSizeException | BadPaddingException e) {
			e.printStackTrace();
			return null;
		}
		return newMessage;
	}


	public static String decryptDES(byte[] messageCode, SecretKey keyDES) {
		String decryptedDES = "";
		byte[] messageClair = cryptDES(messageCode, Cipher.DECRYPT_MODE, keyDES, CIPHER_DES_MODE);
		if (messageClair != null) {
			decryptedDES = new String(messageClair);
		}
		return decryptedDES;
	}
	
	public static byte[] encryptRSA(byte[] messageClair, PublicKey publicKeyRSA) {
		return cryptDES(messageClair, Cipher.ENCRYPT_MODE, publicKeyRSA, CIPHER_RSA_MODE);
	}
	
	public static byte[] decryptByteRSA(byte[] messageCode, PrivateKey privateKeyRSA) {
		return cryptDES(messageCode, Cipher.DECRYPT_MODE, privateKeyRSA, CIPHER_RSA_MODE);
	}
}
