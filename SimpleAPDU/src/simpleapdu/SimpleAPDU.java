package simpleapdu;

import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import applets.AlmostSecureApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import javacard.framework.OwnerPIN;
import javacard.security.AESKey;
import javacard.security.Key;
import javacard.security.KeyBuilder;
import javacard.security.KeyPair;
import javacard.security.RandomData;
import javacard.security.Signature;
import javacardx.crypto.Cipher;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;
import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.util.Arrays;
import org.bouncycastle.util.BigIntegers;


/**
 * Test class.
 * Note: If simulator cannot be started try adding "-noverify" JVM parameter
 *
 * @author Petr Svenda (petrs), Dusan Klinec (ph4r05)
 */
public class SimpleAPDU {
    private static String APPLET_AID = "482871d58ab7465e5e05";
    private static byte APPLET_AID_BYTE[] = Util.hexStringToByteArray(APPLET_AID);

    private static final String STR_APDU_GETRANDOM = "B054100000";
    
    private static final Integer BIGINT_LENGTH = 32; 
    private static final Integer POINT_LENGTH = 33;
    private static final Integer JPAKE1_TOTAL_LENGTH = 196; 
    private static final Integer JPAKE2_TOTAL_LENGTH = 196; 
    private static final Integer JPAKE3_TOTAL_LENGTH = 98;
    private static final Integer JPAKE4_TOTAL_LENGTH = 98;
    private static final boolean COMPRESS_POINTS = true;
    private static final Integer ZKP_LENGTH = BIGINT_LENGTH + POINT_LENGTH;
    
    private static final short RESPONSE_OK = (short) 0x9000;
    
    private static byte[] CARD_ID   = null;
    private static byte[] PC_ID     = null;
    private static byte[] PIN       = null;
    private static BigInteger SHARED_BIG_INT = null;
    
    private ECParameterSpec ecSpec  = null;
    private ECCurve.Fp  ecCurve     = null;
    private BigInteger n        = null;
    private ECPoint G           = null;
    private ECPoint pointG1     = null;
    private ECPoint pointG2     = null;
    private ECPoint pointG3     = null;
    private ECPoint pointG4     = null;
    private ECPoint GA          = null;
    private ECPoint A           = null;
    
    private BigInteger x1 = null;
    private BigInteger x2 = null;
    
    private ECPoint pointK = null;
    private BigInteger key = null;
    
    
    private AESKey m_aesKey        = null;
    private Cipher m_encryptCipher = null;
    private Cipher m_decryptCipher = null;
    private RandomData m_secureRandom = null;
    protected MessageDigest m_hash = null;
    private Signature m_sign    = null;
    private KeyPair m_keyPair   = null;
    private Key m_privateKey    = null;
    private Key m_publicKey     = null;
        
    
    protected SimpleAPDU() {
        CARD_ID = new byte[] {'c', 'a', 'r', 'd'};
        PC_ID = new byte[] {'u', 's', 'e', 'r'};
        PIN = new byte[] {0x01, 0x02, 0x03, 0x04};
        SHARED_BIG_INT = BigIntegers.fromUnsignedByteArray(PIN);
        ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
        ecCurve = (ECCurve.Fp) ecSpec.getCurve();
        G = ecSpec.getG();
        n = ecSpec.getN();
        
        // CREATE AES KEY OBJECT
        m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
        
        // CREATE OBJECTS FOR CBC CIPHERING
        m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
        m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

        // CREATE RANDOM DATA GENERATORS
        m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);
    }
    
    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        
        try {
            SimpleAPDU main = new SimpleAPDU();
            // CardManager abstracts from real or simulated card, provide with applet AID
            final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE); 
        
            // Get default configuration for subsequent connection to card (personalized later)
            final RunConfig runCfg = RunConfig.getDefaultConfig();

            // Running in the simulator 
            runCfg.setAppletToSimulate(AlmostSecureApplet.class); // main class of applet to simulate
            runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

            // Connect to first available card
            // NOTE: selects target applet based on AID specified in CardManager constructor
            System.out.print("Connecting to card...");
            if (!cardMngr.Connect(runCfg)) {
                System.out.println(" Failed.");
            }
            System.out.println(" Done.");

        
            if (! main.CreateSecureChannel(cardMngr)) {
                cardMngr.transmit(main.deselectAPDU());
            }
            
            /*
            
            Sending messeges
            
            */
            cardMngr.transmit(main.deselectAPDU());
                             
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    private boolean CreateSecureChannel(CardManager cardMngr)  throws Exception {
        
        byte[] APDUdata = JPAKE1();
        if (APDUdata.length != JPAKE1_TOTAL_LENGTH) {
            // Generated APDU data has different length than they should have
            return false;
        }
        
        // Send to card ang get the response
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x01, 0x00, 0x00, APDUdata, JPAKE2_TOTAL_LENGTH)); // Use other constructor for CommandAPDU
        byte[] responseData2 = response2.getData();
        if ((short) response2.getSW() != RESPONSE_OK || responseData2.length != JPAKE2_TOTAL_LENGTH) {
            // Processing of APDU on card was not successful or the response has bad length
            return false;
        }
        
        if (!JPAKE2(responseData2)){
            // ZKP for x3 (or x4) was not correct
            System.out.println(" JPAKE2 fail.");
            return false;
        }
        
        byte[] APDUdata3 = JPAKE3();
        if (APDUdata3.length != JPAKE3_TOTAL_LENGTH) {
            // Generated APDU data has different length than they should have
            return false;
        }
        
        final ResponseAPDU response4 = cardMngr.transmit(new CommandAPDU(0xB0, 0x02, 0x00, 0x00, APDUdata3, JPAKE4_TOTAL_LENGTH)); // Use other constructor for CommandAPDU
        byte[] responseData4 = response4.getData();
        if ((short) response4.getSW() != RESPONSE_OK || responseData4.length != JPAKE4_TOTAL_LENGTH) {
            // Processing of APDU on card was not successful or the response has bad length
            return false;
        }
        
        if (!JPAKE4(responseData4)){
            // ZKP for x4 * s was not correct
            System.out.println(" JPAKE4 fail.");
            return false;
        }
        
        return true;
    }
    

    private CommandAPDU deselectAPDU() {
        /* Creates deselect APDU */
        return new CommandAPDU(0xB0, 0x03, 0x00, 0x00);
    }

    private byte[] JPAKE1() throws IOException {
        /* get random x1, x2 from [1, n-1] */
        x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	
        /* compute G x [x1], G x [x2] */
        pointG1 = G.multiply(x1);
        pointG2 = G.multiply(x2);
        
        /* create ZKP of x1 and x2 (Schnorr) */
        SchnorrZKP zkpx1 = generateZKP(G, n, x1, pointG1, PC_ID);
        SchnorrZKP zkpx2 = generateZKP(G, n, x2, pointG2, PC_ID);

        /* Encode pointG1, pointG2, zkpx1, zkpx2 */
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(pointG1.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx1.toByteArray());
        
        byteStream.write(pointG2.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2.toByteArray());
                
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }
    
    private boolean JPAKE2(byte[] response) {
        /* Parse the response */
        ByteArrayInputStream stream = new ByteArrayInputStream(response);
        byte[] pointBytes = new byte[POINT_LENGTH];
        byte[] zkpBytes = new byte[ZKP_LENGTH];
        
        /* Get G3 = G x [x3], and a ZKP of x3 */
        stream.read(pointBytes, 0, POINT_LENGTH);
        pointG3 = ecCurve.decodePoint(pointBytes);
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx3 = new SchnorrZKP(zkpBytes);
        
        /* Get G4 = G x [x4], and a ZKP of x4 */
        stream.read(pointBytes, 0, POINT_LENGTH);
        pointG4 = ecCurve.decodePoint(pointBytes);    
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx4 = new SchnorrZKP(zkpBytes);
        
        /* Verify ZKP of x3, x4 */
        if (verifyZKP(G, pointG3, zkpx3.getV(), zkpx3.getr(), CARD_ID) ){
            System.out.println("ZKP x3 OK.");
        } else {
            System.out.println("ZKP x3 failed.");
            return false;
        }
        if (verifyZKP(G, pointG4, zkpx4.getV(), zkpx4.getr(), CARD_ID) ){
            System.out.println("ZKP x4 OK.");
        } else {
            System.out.println("ZKP x4 failed.");
            return false;
        }
        return true;
    }
    
    private byte[] JPAKE3() throws IOException {
        /* Compute GA = G1 + G3 + G4 */
        GA = pointG1.add(pointG3).add(pointG4).normalize(); 
    	
        /* Compute A = (G1 + G3 + G4) x [x2*s] and a ZKP for x2*s */
        A = GA.multiply(x2.multiply(SHARED_BIG_INT).mod(n));				
    	SchnorrZKP zkpx2s = generateZKP(GA, n, x2.multiply(SHARED_BIG_INT).mod(n), A, PC_ID);
		
        /* Encode A and zkpx2s and send data to card */
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(A.normalize().getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2s.toByteArray());
        
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }
    
    private boolean JPAKE4(byte[] response){
        ByteArrayInputStream stream = new ByteArrayInputStream(response);
        byte[] pointBytes = new byte[POINT_LENGTH];
        byte[] zkpBytes = new byte[ZKP_LENGTH];
        
        /* Compute GB = G1 + G2 + G3 */
        ECPoint GB = pointG1.add(pointG2).add(pointG3).normalize();
        
        /* Get B = (G1 + G2 + G3) x [x4*s] and a ZKP for x4*s */
        stream.read(pointBytes, 0, POINT_LENGTH);
        ECPoint B = ecCurve.decodePoint(pointBytes).normalize();
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx4s = new SchnorrZKP(zkpBytes);   
        
        /* Verify ZKP of x4*s */
        if (verifyZKP(GB, B, zkpx4s.getV(), zkpx4s.getr(), CARD_ID) ){
            System.out.println("ZKP x4*s OK.");
        } else {
            System.out.println("ZKP x4*s failed.");
            return false;
        }
        
        /* Computed K = (B - (G4 x [x2*s])) x [x2] to get a shared secret */
        pointK = B.subtract(pointG4.multiply(x2.multiply(SHARED_BIG_INT))).multiply(x2).normalize();
        key = getSHA256(pointK.normalize().getXCoord().toBigInteger());
        return true;
    }
    
  
    
    private BigInteger getSHA256(ECPoint G, ECPoint V, ECPoint D, byte[] userID) {
    	MessageDigest sha256 = null;
    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		
    		byte[] GBytes = G.getEncoded(true);
    		byte[] VBytes = V.getEncoded(true);
    		byte[] XBytes = D.getEncoded(true);
    		
    		// It's good practice to prepend each item with a 4-byte length
    		sha256.update(ByteBuffer.allocate(4).putInt(GBytes.length).array());
    		sha256.update(GBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(VBytes.length).array());
    		sha256.update(VBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(XBytes.length).array());
    		sha256.update(XBytes);
    		
    		sha256.update(ByteBuffer.allocate(4).putInt(userID.length).array());
    		sha256.update(userID);    	
   		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return new BigInteger(sha256.digest());
    }
    
    private BigInteger getSHA256(BigInteger toHash) {
    	MessageDigest sha256 = null;
    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		sha256.update(toHash.toByteArray());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return new BigInteger(1, sha256.digest()); // 1 for positive int
    }
    
    private SchnorrZKP generateZKP (ECPoint G, BigInteger n, BigInteger d, ECPoint D, byte[] userID) {
            /* Generate a proof of knowledge of scalar for D = [d] x G */
            
            /* Generate a random v from [1, n-1], and compute V = [v] x G */
            BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
       			n.subtract(BigInteger.ONE), new SecureRandom());
            ECPoint V = G.multiply(v);
                
            BigInteger c = getSHA256(G, V, D, userID); // compute hash H(G || V || D || UserID)
            BigInteger r = v.subtract(d.multiply(c)).mod(n); // r = v-d*c mod n 
            return new SchnorrZKP(V,r);
    }
    
    public boolean verifyZKP(ECPoint generator, ECPoint X, ECPoint V, BigInteger r, byte[] userID) {
       
        /* ZKP: {V=G*v, r} */              
        BigInteger h = getSHA256(generator, V, X, userID);
       
        // Public key validation based on p. 25
        // http://cs.ucsb.edu/~koc/ccs130h/notes/ecdsa-cert.pdf
       
        // 1. X != infinity
        if (X.isInfinity()){
            return false;
        }
       
        // 2. Check x and y coordinates are in Fq, i.e., x, y in [0, q-1]
        if (X.getXCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.getXCoord().toBigInteger().compareTo(ecCurve.getQ().subtract(BigInteger.ONE)) == 1 ||
                X.getYCoord().toBigInteger().compareTo(BigInteger.ZERO) == -1 ||
                X.getYCoord().toBigInteger().compareTo(ecCurve.getQ().subtract(BigInteger.ONE)) == 1) {
            return false;
        }
                   
        // 3. Check X lies on the curve
        try {
            ecCurve.decodePoint(X.getEncoded(false));
        }
        catch(Exception e){
            e.printStackTrace();
            return false;
        }
       
        // 4. Check that nX = infinity.
        // It is equivalent - but more more efficient - to check the coFactor*X is not infinity
        if (X.multiply(ecSpec.getH()).isInfinity()) {
            return false;
        }
       
        // Now check if V = G*r + X*h.
        // Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
        if (V.equals(generator.multiply(r).add(X.multiply(h.mod(n))))) {
            return true;
        }
        else {
            return false;
        }
    }
    
    private class SchnorrZKP {
    	/*
          Class which holds a number and a point corresponding to some ZKP.
        */
    	private ECPoint V = null;
    	private BigInteger r = null;
    			
    	private SchnorrZKP(ECPoint V, BigInteger r) {
            this.V = V;
            this.r = r;  
    	}
        
        private SchnorrZKP(byte[] encoded){
            /*
              Constructor which decodes a point and a number from byte array.
            */
            this.V = ecCurve.decodePoint(Arrays.copyOfRange(encoded, 0, POINT_LENGTH)).normalize();
            this.r = new BigInteger(1,Arrays.copyOfRange(encoded, POINT_LENGTH, ZKP_LENGTH));
        }
        
	private ECPoint getV() {
            return V;
    	}
    	
    	private BigInteger getr() {
            return r;
    	}
        
        private byte[] toByteArray() throws IOException {
            /*
              Encodes ZKP (the point and the number) to bytes
            */
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(this.getV().normalize().getEncoded(COMPRESS_POINTS));
            byte[] array = this.getr().toByteArray();
            if(array.length > 32) {
                array = java.util.Arrays.copyOfRange(array, array.length-32, array.length);
            }
            int diff = BIGINT_LENGTH - array.length;
            if (diff > 0){
                byteStream.write(new byte[diff]);
            }
            byteStream.write(array);
            byte[] retBytes = byteStream.toByteArray();
            byteStream.close();
            return retBytes;
        }
    }
    
    public class AlmostCard {
        private BigInteger x3 = null;
        private BigInteger x4 = null;
        private BigInteger key = null; 
        private ECPoint pointG1 = null;    	
        private ECPoint pointG2 = null;
        private ECPoint pointG3 = null;    	
        private ECPoint pointG4 = null;
        private ECPoint pointK = null;
        
        public boolean compareResultJPAKE(BigInteger otherKey){
            /* Returns true if this.key == other.key */
            if (this.key.equals(otherKey)) {
                System.out.println("They shared a key.");
                return true;
            } else {
                System.out.println("The key is not the same");
                return false;
            }
        }
        
        public byte[] processJPAKE(byte[] inApdu) throws IOException {
            /*
            This part should run on card.
            It processes data of first APDU in JPAKE and creates response.
            */
            ByteArrayInputStream stream = new ByteArrayInputStream(inApdu); 
            byte[] pointBytes = new byte[POINT_LENGTH];
            byte[] zkpBytes = new byte[ZKP_LENGTH];
            
            /* Get G1 = G x [x1], and a ZKP of x1 */
            stream.read(pointBytes, 0, POINT_LENGTH);
            pointG1 = ecCurve.decodePoint(pointBytes);
            stream.read(zkpBytes, 0, ZKP_LENGTH);
            SchnorrZKP zkpx1 = new SchnorrZKP(zkpBytes);
            
            /* Get G2 = G x [x2], and a ZKP of x2 */
            stream.read(pointBytes, 0, POINT_LENGTH);
            pointG2 = ecCurve.decodePoint(pointBytes);
            stream.read(zkpBytes, 0, ZKP_LENGTH);
            SchnorrZKP zkpx2 = new SchnorrZKP(zkpBytes);
            
            /* Verify ZKP of x1, x2 */
            if (verifyZKP(G, pointG1, zkpx1.getV(), zkpx1.getr(), PC_ID) ){
                System.out.println("ZKP x1 OK.");
            } else {
                System.out.println("ZKP x1 failed.");
            }
            if (verifyZKP(G, pointG2, zkpx2.getV(), zkpx2.getr(), PC_ID) ){
                System.out.println("ZKP x2 OK.");
            } else {
                System.out.println("ZKP x2 failed.");
            } 
            
            /* get random x3, x4 from [1, n-1] */
            x3 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
            x4 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
            
            /* compute G x [x3], G x [x4] */
            pointG3 = G.multiply(x3);
            pointG4 = G.multiply(x4);
            
            /* create ZKP of x3 and x4 (Schnorr) */
            SchnorrZKP zkpx3 = generateZKP(G, n, x3, pointG3, CARD_ID);
    	    SchnorrZKP zkpx4 = generateZKP(G, n, x4, pointG4, CARD_ID);

            /* Compute GB = G1 + G2 + G3 */
            ECPoint GB = pointG1.add(pointG2).add(pointG3); 
            
            /* Compute B = (G1 + G2 + G3) x [x4*s] and a ZKP for x4*s */
            ECPoint B = GB.multiply(x4.multiply(SHARED_BIG_INT).mod(n));
            SchnorrZKP zkpx4s = generateZKP(GB, n, x4.multiply(SHARED_BIG_INT).mod(n), B, CARD_ID);
        
            /* Create response and return it = send it back*/
            ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
            byteStream.write(pointG3.getEncoded(COMPRESS_POINTS));
            byteStream.write(zkpx3.toByteArray());
            byteStream.write(pointG4.getEncoded(COMPRESS_POINTS));
            byteStream.write(zkpx4.toByteArray());
            byteStream.write(B.getEncoded(COMPRESS_POINTS));
            byteStream.write(zkpx4s.toByteArray());
            byte[] response = byteStream.toByteArray();
            byteStream.close();
            return response;
        }
        
        public void processJPAKE2(byte[] inApdu) throws IOException {
            /*
            This part should run on card.
            It processes data of second APDU in JPAKE and coputes shared secret.
            */
            ByteArrayInputStream stream = new ByteArrayInputStream(inApdu); 
            byte[] pointBytes = new byte[POINT_LENGTH];
            byte[] zkpBytes = new byte[ZKP_LENGTH];
            
            /* Compute GA = G1 + G3 + G4 */
            ECPoint GA = pointG1.add(pointG3).add(pointG4);
            
            /* Get A = (G1 + G3 + G4) x [x2*s] and a ZKP for x2*s */
            stream.read(pointBytes, 0, POINT_LENGTH);
            ECPoint A = ecCurve.decodePoint(pointBytes);
            
            stream.read(zkpBytes, 0, ZKP_LENGTH);
            SchnorrZKP zkpx2s = new SchnorrZKP(zkpBytes);
            stream.close();
            
            /* Verify ZKP of x2*s */
            if (verifyZKP(GA, A, zkpx2s.getV(), zkpx2s.getr(), PC_ID) ){
                System.out.println("ZKP x2*s OK.");
            } else {
                System.out.println("ZKP x2*s failed.");
            }
            
            /* Computed K = (A - (G2 x [x4*s])) x [x4] to get a shared secret */
            this.pointK = A.subtract(pointG2.multiply(x4.multiply(SHARED_BIG_INT))).multiply(x4).normalize();
            this.key = getSHA256(pointK.getXCoord().toBigInteger());
        }
        
    }    
}
