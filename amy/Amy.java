import javax.crypto.*;
import java.io.*;
import java.net.Socket;
import java.net.UnknownHostException;
import java.security.GeneralSecurityException;
import java.security.InvalidKeyException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;

// Amy knows Berisign's public key
// Amy receives and verifies Bryan's public key using
// Amy sends Bryan session (AES) key
// Amy receives messages from Bryan, decrypts and saves them to file

class Amy {

    String bryanIP;  // ip address of Bryan
    int bryanPort;   // port Bryan listens to
    Socket connectionSkt;  // socket used to talk to Bryan
    private ObjectOutputStream toBryan;   // to send session key to Bryan
    private ObjectInputStream fromBryan;  // to read encrypted messages from Bryan
    private Crypto crypto;        // object for encryption and decryption
    // file to store received and decrypted messages
    public static final String MESSAGE_FILE = "msgs.txt";

    public static void main(String[] args) {

        // Check if the number of command line argument is 2
        if (args.length != 2) {
            System.err.println("Usage: java Amy BryanIP BryanPort");
            System.exit(1);
        }

        new Amy(args[0], args[1]);
    }

    // Constructor
    public Amy(String ipStr, String portStr) {

        this.crypto = new Crypto();

        this.bryanIP = ipStr;
        this.bryanPort = Integer.parseInt(portStr);

        // Create a socket to initiate a TCP connection to Bryan
        try {
            this.connectionSkt = new Socket(bryanIP, bryanPort);
        } catch (UnknownHostException e) {
            e.printStackTrace();
        } catch (IOException e) {
            System.err.println("Error creating connection socket");
            System.exit(1);
        }

        // Set up input and output streams
        try {
            this.toBryan = new ObjectOutputStream(this.connectionSkt.getOutputStream());
            this.fromBryan = new ObjectInputStream(this.connectionSkt.getInputStream());
        } catch (IOException e) {
            System.err.println("Error creating input and output streams from/to Bryan");
            System.exit(1);
        }

        // Obtain Bryan's RSA public key
        receivePublicKey();

        // Send session key to Bryan
        sendSessionKey();

        // Receive encrypted messages from Bryan,
        // decrypt and save them to file
        receiveMessages();
    }

    private void receivePublicKey() {
        try {
            PublicKey pubKey = (PublicKey) fromBryan.readObject(); // First receive the RSA public key
            byte[] md5Digest = (byte[]) fromBryan.readObject(); // Second receive the byte array containing encrypted signature
            if (crypto.isValidPublicKey(pubKey, md5Digest)) {
                System.out.println("Bryan's public key successfully received and verified");
            } else {
                System.out.println("Bryan's public key could not be verified");
                System.exit(1);
            }
        } catch (IOException e) {
            System.out.println("IO Exception at receiving Bryan's public key");
            System.exit(1);
        } catch (ClassNotFoundException e) {
            System.out.println("ClassNotFoundException at receiving Bryan's public key");
            System.exit(1);
        }
    }

    // Send session key to Bryan
    public void sendSessionKey() {
        try {
            this.toBryan.writeObject(this.crypto.getSessionKey());
        } catch (IOException e) {
            System.err.println("Error sending session key to Bryan");
            System.exit(1);
        }
    }

    // Receive messages one by one from Bryan, decrypt and write to file
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
                SealedObject encryptedMsg = (SealedObject) this.fromBryan.readObject();
                String messageLine = this.crypto.decryptMsg(encryptedMsg);
                out.println(messageLine);
            } catch (IOException e) {
                System.err.println("Error reading encrypted message from Bryan");
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

        private PublicKey bryanPublicKey;
        // Amy generates a new session key for each communication session
        private SecretKey sessionKey;
        // Berisign's public key, to be read from file
        private PublicKey berisignPublicKey;

        // File that contains Bryan' public key
        public static final String PUBLIC_KEY_FILE = "berisign.pub";

        // Constructor
        public Crypto() {
            // Read Berisign's public key from file
            readBerisignPublicKey();
            // Generate session key dynamically
            initSessionKey();
        }

        // Read Berisign's public key from file
        public void readBerisignPublicKey() {
            // key is stored as an object and need to be read using ObjectInputStream.
            // See how Bryan read his private key as an example.
            try {
                ObjectInputStream ois = new ObjectInputStream(new FileInputStream(PUBLIC_KEY_FILE));
                this.berisignPublicKey = (PublicKey) ois.readObject();
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

            // Amy must use the same RSA key/transformation as Bryan specified
            Cipher cipher = null;
            try {
                cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.ENCRYPT_MODE, this.bryanPublicKey);
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

            // Amy and Bryan use the same AES key/transformation
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

            return (String) plainText;
        }

        // Compare received public key and public key in received MD5 Digest to check validity
        public boolean isValidPublicKey(PublicKey pubKey, byte[] md5Digest) {
            String name = "bryan"; // Part of md5 digest

            byte[] receivedDigest = null;
            byte[] decryptedDigest = null;

            try {
                // Decrypt the message digest using berisign's public key
                Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
                cipher.init(Cipher.DECRYPT_MODE, berisignPublicKey);
                decryptedDigest = cipher.doFinal(md5Digest);

                // Get the byte arrays of the name and the pubkey, which make up the digest
                byte[] nameBytes = name.getBytes("US-ASCII");
                byte[] publicKeyBytes = pubKey.getEncoded();

                // Construct a digest using the pubkey received
                MessageDigest publicKeyMd5Digest = MessageDigest.getInstance("MD5");
                publicKeyMd5Digest.update(nameBytes);
                publicKeyMd5Digest.update(publicKeyBytes);
                receivedDigest = publicKeyMd5Digest.digest(); // to be compared to decrypted
            } catch (NoSuchAlgorithmException nae) {
                System.err.println("Error: MD5 algorithm not found when validating Bryan's public key");
                System.exit(1);
            } catch (GeneralSecurityException ge) { // Encompasses NoSuchAlgorithmException, NoSuchPaddingException, BadPaddingException, IllegalBlockSizeException, InvalidKeyException, GeneralSecurityException
                System.out.println("Error:MD5 signature does not match");
                System.exit(1);
            } catch (UnsupportedEncodingException e) {
                System.err.println("Error: US-ACSII encoding not supported when validating Bryan's public key");
                System.exit(1);
            }

            // Check if the received & constructed and decrypted digests are equal
            if (MessageDigest.isEqual(receivedDigest, decryptedDigest)) {
                this.bryanPublicKey = pubKey; // Set to the validated pubkey
                return true;
            } else {
                return false;
            }
        }
    }
}