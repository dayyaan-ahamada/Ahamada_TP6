package model;

public class EncryptedMessage {

	byte[] encryptedKeyDES;
	byte[] encryptedMessage;
	
	public EncryptedMessage(byte[] message, byte[] key){
		encryptedMessage = message;
		encryptedKeyDES = key;
	}

	public byte[] getEncryptedKeyDES() {
		return encryptedKeyDES;
	}
	
	public byte[] getEncryptedMessage() {
		return encryptedMessage;
	}
	
}
