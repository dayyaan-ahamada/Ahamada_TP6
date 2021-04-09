package view;

import controller.ControllerEncryption;
import model.EncryptedMessage;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.KeyPair;
import java.security.PrivateKey;
import java.security.PublicKey;

import javax.crypto.SecretKey;

public class Server {

    private final PublicKey publicKeyRSA;
    private final PrivateKey privateKeyRSA;

    private EncryptedMessage encryptedMessage;


    public Server() {
        KeyPair keyPair = ControllerEncryption.getRSAKeys();
        publicKeyRSA = keyPair != null ? keyPair.getPublic() : null;
        privateKeyRSA = keyPair != null ? keyPair.getPrivate() : null;

    }

    public void connexion() {
        ServerSocket sockserv = null;
        ObjectInputStream in;
        ObjectOutputStream out;
        try {
            sockserv = new ServerSocket();
            sockserv.bind(new InetSocketAddress("127.0.0.1",444));
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            while (true) {
                try {
                    Socket sockcli = sockserv.accept();

                    in = new ObjectInputStream(sockcli.getInputStream());
                    out = new ObjectOutputStream(sockcli.getOutputStream());

                    out.writeObject(publicKeyRSA.getEncoded());

                    boolean continu = true;
                    byte[] message;
                    byte[] keyDESCode;
                    while (continu) {
                        try {
                            message = (byte[]) in.readObject();
                        } catch (ClassNotFoundException e) {
                            e.printStackTrace();
                            return;
                        }
                        if (new String(message).equals("EXIT"))
                            continu = false;
                        else {
                            try {
                                keyDESCode = (byte[]) in.readObject();
                            } catch (ClassNotFoundException e) {
                                e.printStackTrace();
                                return;
                            }
                            setEncryptedMessage(new EncryptedMessage(message, keyDESCode));

                            System.out.println(decryptMessage());
                        }
                    }
                    sockcli.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        } finally {
            try {
                sockserv.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }

    public void setEncryptedMessage(EncryptedMessage em) {
        encryptedMessage = em;
    }

    public String decryptMessage() {
        if (encryptedMessage == null) {
            return null;
        }
        byte[] byteKeyDES = ControllerEncryption.decryptByteRSA(encryptedMessage.getEncryptedKeyDES(), privateKeyRSA);
        SecretKey keyDES = ControllerEncryption.getDESKeyFromByteArray(byteKeyDES);

        return ControllerEncryption.decryptDES(encryptedMessage.getEncryptedMessage(), keyDES);
    }

    public static void main(String[] args) {
        Server s = new Server();
        s.connexion();
    }
}
