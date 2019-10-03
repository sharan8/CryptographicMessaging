import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

// Alice knows Bob's public key
// Alice sends Bob session (AES) key
// Alice receives messages from Bob, decrypts and saves them to file

class Alice {  // Alice is a TCP client
    
    String bobIP;  // ip address of Bob
    int bobPort;   // port Bob listens to
    Socket connectionSkt;  // socket used to talk to Bob
    private ObjectOutputStream toBob;   // to send session key to Bob
    private ObjectInputStream fromBob;  // to read encrypted messages from Bob
    private Crypto crypto;        // object for encryption and decryption
    // file to store received and decrypted messages
    public static final String MESSAGE_FILE = "msgs.txt";
    
    public static void main(String[] args) {
        
        // Check if the number of command line argument is 2
        if (args.length != 2) {
            System.err.println("Usage: java Alice BobIP BobPort");
            System.exit(1);
        }
        
        new Alice(args[0], args[1]);
    }
    
    // Constructor
    public Alice(String ipStr, String portStr) {

        this.crypto = new Crypto();

        this.bobIP = ipStr;
        this.bobPort = Integer.parseInt(portStr);

        // Create a socket to initiate a TCP connection to Bob
        try {
            this.connectionSkt = new Socket(bobIP, bobPort);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error creating connection socket");
            System.exit(1);
        }

        // Set up input and output streams
        try {
            this.toBob = new ObjectOutputStream(this.connectionSkt.getOutputStream());
            this.fromBob = new ObjectInputStream(this.connectionSkt.getInputStream());
        } catch (IOException e) {
            System.err.println("Error creating input and output streams from/to Bob");
            System.exit(1);
        }

        // Send session key to Bob
        sendSessionKey();
        
        // Receive encrypted messages from Bob,
        // decrypt and save them to file
        receiveMessages();
    }
    
    // Send session key to Bob
    public void sendSessionKey() {
        try {
            this.toBob.writeObject(this.crypto.getSessionKey());
        } catch (IOException e) {
            System.err.println("Error sending session key to Bob");
            System.exit(1);
        }
    }
    
    // Receive messages one by one from Bob, decrypt and write to file
    public void receiveMessages() {
        PrintWriter out = null;
        try {
            out = new PrintWriter(MESSAGE_FILE);
        } catch (FileNotFoundException e) {
            System.err.println("MESSAGE_FILE not found to write to");
        }

        // Assume there are exactly 10 lines to read
        for (int i = 0; i < 10; i++) {
            try {
                SealedObject encryptedMsg = (SealedObject) this.fromBob.readObject();
                String messageLine = this.crypto.decryptMsg(encryptedMsg);
                out.println(messageLine);
            } catch (IOException e) {
                System.err.println("Error reading encrypted message from Bob");
            } catch (ClassNotFoundException e) {
                System.err.println("Class of serialized object could not be found");
            }
        }

        System.out.println("Messages received and written to file " + MESSAGE_FILE);

        out.close();
    }
    
    /*****************/
    /** inner class **/
    /*****************/
    class Crypto {
        
        // Bob's public key, to be read from file
        private PublicKey pubKey;
        // Alice generates a new session key for each communication session
        private SecretKey sessionKey;
        // File that contains Bob' public key
        public static final String PUBLIC_KEY_FILE = "bob.pub";
        
        // Constructor
        public Crypto() {
            // Read Bob's public key from file
            readPublicKey();
            // Generate session key dynamically
            initSessionKey();
        }
        
        // Read Bob's public key from file
        public void readPublicKey() {
            // key is stored as an object and need to be read using ObjectInputStream.
            // See how Bob read his private key as an example.
            try {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                this.pubKey = (PublicKey) ois.readObject();
                ois.close();
            } catch (FileNotFoundException e) {
                System.err.println("Public key file not found!");
                System.exit(1);
            } catch (IOException e) {
                System.err.println("Error reading public key from file");
                System.exit(1);
            } catch (ClassNotFoundException e) {
                System.err.println("Error: cannot typecast to class PublicKey");
                System.exit(1);
            }

            System.out.println("Public key read from file " + PUBLIC_KEY_FILE);
        }
        
        // Generate a session key
        public void initSessionKey() {
            // suggested AES key length is 128 bits
            try {
                KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
                keyGenerator.init(128);
                this.sessionKey = keyGenerator.generateKey();
            } catch (NoSuchAlgorithmException e) {
                System.err.println("No provider supports a KeyGeneratorSpi implementation for the AES algorithm");
            }
        }
        
        // Seal session key with RSA public key in a SealedObject and return
        public SealedObject getSessionKey() {
            
            // Alice must use the same RSA key/transformation as Bob specified
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, this.pubKey);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("No provider supports a KeyGeneratorSpi implementation for the RSA/ECB/PKCS1Padding algorithm");
            } catch (NoSuchPaddingException e) {
                System.err.println("NoSuchPaddingException thrown");
            } catch (InvalidKeyException e) {
                System.err.println("Given key is unable to initialize the cipher");
            }

            // RSA imposes size restriction on the object being encrypted (117 bytes).
            // Instead of sealing a Key object which is way over the size restriction,
            // we shall encrypt AES key in its byte format (using getEncoded() method).
            SealedObject sessionKeyObject = null;
            try {
                sessionKeyObject = new SealedObject(sessionKey.getEncoded(), cipher);
            } catch (IOException e) {
                System.err.println("Error serializing sessionKey.getEncoded() object");
            } catch (IllegalBlockSizeException e) {
                System.err.println("Error with block size of the given cipher");
            }

            return sessionKeyObject;
        }
        
        // Decrypt and extract a message from SealedObject
        public String decryptMsg(SealedObject encryptedMsgObj) {

            // Alice and Bob use the same AES key/transformation
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
                cipher.init(Cipher.DECRYPT_MODE, sessionKey);
            } catch (NoSuchAlgorithmException e) {
                System.err.println("No provider supports a KeyGeneratorSpi implementation for the RSA/ECB/PKCS1Padding algorithm");
            } catch (NoSuchPaddingException e) {
                System.err.println("NoSuchPaddingException thrown when decrypting message");
            } catch (InvalidKeyException e) {
                System.err.println("Given key is unable to initialize the cipher");
            }

            String plainText = null;
            try {
                plainText = (String) encryptedMsgObj.getObject(cipher);
            } catch (BadPaddingException e) {
                System.err.println("BadPaddingException thrown when decrypting message");
            } catch (IllegalBlockSizeException e) {
                System.err.println("Error with block size of the given cipher");
            } catch (IOException e) {
                System.err.println("IOException when decrypting message");
            } catch (ClassNotFoundException e) {
                System.err.println("ClassNotFoundException when decrypting message");
            }

            return plainText;
        }
    }
}