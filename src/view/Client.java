package view;

import controller.ControllerEncryption;

import java.io.IOException;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.net.Socket;
import java.net.SocketAddress;
import java.security.PublicKey;
import java.util.Scanner;
import javax.crypto.SecretKey;

public class Client {

    private final SecretKey keyDES;

    public Client() {
        keyDES = ControllerEncryption.getDESKey();
    }

    public void connexion() {
        ObjectInputStream in;
        ObjectOutputStream out;
        Scanner sc = new Scanner(System.in);

        Socket sock = new Socket();

        try {
            sock = new Socket("127.0.0.1", 444);
        } catch (IOException e) {
            e.printStackTrace();
        }
        try {
            while (true)
                try {
                    sock.connect(new SocketAddress() {
                        private static final long serialVersionUID = 6060331106056561656L;
                    });
                    System.out.println("Connexion réussie");
                    in = new ObjectInputStream(sock.getInputStream());
                    out = new ObjectOutputStream(sock.getOutputStream());
                    byte[] keyRSA;
                    try {
                        keyRSA = (byte[]) in.readObject();
                    } catch (ClassNotFoundException e) {
                        e.printStackTrace();
                        return;
                    }
                    PublicKey serveurPublicKeyRSA = ControllerEncryption.getRSAKeyFromByteArray(keyRSA);

                    boolean continu = true;
                    String message;
                    byte[] keyDESCode;
                    while (continu) {
                        System.out.print("Entrez un message ou écrivez EXIT pour arrêter : ");
                        message = sc.nextLine();
                        out.writeObject(message.getBytes());
                        if (message.equals("EXIT")) {
                            continu = false;
                        } else {
                            keyDESCode = ControllerEncryption.encryptRSA(keyDES.getEncoded(), serveurPublicKeyRSA);
                            out.writeObject(keyDESCode);
                        }
                    }
                    sock.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
        } finally {
            try {
                sock.close();
            } catch (IOException e) {
                e.printStackTrace();
            }
        }
    }
    public static void main(String[] args) {
        Client c = new Client();
        c.connexion();
    }
}
