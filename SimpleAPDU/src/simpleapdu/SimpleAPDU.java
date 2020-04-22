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
    private static final boolean COMPRESS_POINTS = true;
    private static final Integer ZKP_LENGTH = BIGINT_LENGTH + POINT_LENGTH;
    
    private static final byte[] PIN = {0x01, 0x02, 0x03, 0x04};
    private static final BigInteger SHARED_BIG_INT = BigIntegers.fromUnsignedByteArray(PIN);
    private static final byte[] CARD_ID = new byte[]{'c', 'a', 'r', 'd'};
    private static final byte[] PC_ID = new byte[]{'u', 's', 'e', 'r'};
    
    private static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    private static ECCurve ecCurve = ecSpec.getCurve();
    private static ECPoint G = ecSpec.getG();
    private static BigInteger q = ecCurve.getCofactor();
    private static BigInteger n = ecSpec.getN();

    private BigInteger x1 = null;
    private BigInteger x2 = null;
    private ECPoint pointG1 = null;
    private ECPoint pointG2 = null;
    private ECPoint pointG3 = null;
    private ECPoint pointG4 = null;
    private ECPoint pointK = null;
    private BigInteger key = null;
    private ECPoint GA = null;
    private ECPoint A = null;
        
    
    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU main = new SimpleAPDU();
            main.demoAlmostSecure();
//            main.jpakeWithoutCard();                 
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }
    
    private void demoAlmostSecure()  throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE); 
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // B) If running in the simulator 
        runCfg.setAppletToSimulate(AlmostSecureApplet.class); // main class of applet to simulate
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        // NOTE: selects target applet based on AID specified in CardManager constructor
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Transmit single APDU
        //final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        //byte[] data = response.getData();
        
        byte[] APDUdata = JPAKE1();
        pointG1 = pointG1.normalize();
        pointG2 = pointG2.normalize();
        System.out.println(APDUdata.length);
        
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(0xB0, 0x01, 0x00, 0x00, APDUdata, 196)); // Use other constructor for CommandAPDU
        byte[] responseData = response.getData();
        
        if (!JPAKE2(responseData)){
            System.out.println(" JPAKE2 fail.");
        }
        byte[] APDUdata3 = JPAKE3();
        System.out.println(APDUdata3.length);
        
        final ResponseAPDU response3 = cardMngr.transmit(new CommandAPDU(0xB0, 0x02, 0x00, 0x00, APDUdata3, 98)); // Use other constructor for CommandAPDU
        byte[] responseData3 = response3.getData();
        
        if (!JPAKE4(responseData)){
            System.out.println(" JPAKE4 fail.");
        }
        
        
        System.out.println(response);
        System.out.println();
        System.out.println(responseData.length);
        System.out.println();
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
        if (verifyZKP(ecCurve, G, n, pointG3, zkpx3, CARD_ID) ){
            System.out.println("ZKP x3 OK.");
        } else {
            System.out.println("ZKP x3 failed.");
            return false;
        }
        if (verifyZKP(ecCurve, G, n, pointG4, zkpx4, CARD_ID) ){
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
        ECPoint GB = pointG1.add(pointG2).add(pointG3);
        
        /* Get B = (G1 + G2 + G3) x [x4*s] and a ZKP for x4*s */
        stream.read(pointBytes, 0, POINT_LENGTH);
        ECPoint B = ecCurve.decodePoint(pointBytes);
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx4s = new SchnorrZKP(zkpBytes);   
        
        /* Verify ZKP of x4*s */
        if (verifyZKP(ecCurve, GB, n, B, zkpx4s, CARD_ID) ){
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
    
/*    private void jpakeWithoutCard() throws IOException {
        AlmostCard card = new AlmostCard();
        
        byte[] apduData1 = new byte[1];
        byte[] response = card.processJPAKE(apduData1);
        
        card.processJPAKE2(apduData2);
        card.compareResultJPAKE(key);
    }
*/    
    private byte[] toByteWithoutSign(BigInteger bigInt) {
        // Not used now
        // removes first byte from BigInteger byte representation
        byte[] array = bigInt.toByteArray();
        
        //if(array.length > 32) {
        //    array = Arrays.copyOfRange(r1Array, r1Array.length-32, r1Array.length);
        //}
        
        byte[] tmp = new byte[array.length - 1];
        System.arraycopy(array, 1, tmp, 0, tmp.length);
        array = tmp;
        return array;
    }
    
    /*
        Encodes data for first APDU in JPAKE
    */
/*    private byte[] jpakeFirstApdu(ECPoint pointG1, ECPoint pointG2, SchnorrZKP zkpx1,SchnorrZKP zkpx2) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(pointG1.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx1.toByteArray());
        
        byteStream.write(pointG2.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2.toByteArray());
                
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }*/

    /*
        Encodes data for second APDU in JPAKE
    */
/*    private byte[] jpakeSecondApdu(ECPoint A, SchnorrZKP zkpx2s) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(A.normalize().getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2s.toByteArray());
        
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }*/
    
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
    
    private boolean verifyZKP(ECCurve ecCurve, ECPoint G, BigInteger n, ECPoint D, SchnorrZKP zkp, byte[] userID) {
    	/* ZKP: {V=G*v, r} */    	    	
    	BigInteger c = getSHA256(G, zkp.getV(), D, userID);
    	
    	// 1. X != infinity
    	if (D.isInfinity()){
    		return false;
    	}
    				
    	// Check X lies on the curve
    	try {
    		ecCurve.decodePoint(D.getEncoded(true));
    	}
    	catch(Exception e){
    		e.printStackTrace();
    		return false;
    	}
    	
    	// 4. Check that nX = infinity.
    	if (!D.multiply(n).isInfinity()) { 
    		return false;
    	}
    	
    	// Now check if V = G*r + X*h. 
    	// Given that {G, X} are valid points on curve, the equality implies that V is also a point on curve.
    	if (zkp.getV().equals(G.multiply(zkp.getr()).add(D.multiply(c.mod(n))))) {
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
            this.V = ecCurve.decodePoint(Arrays.copyOfRange(encoded, 0, POINT_LENGTH));
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
              Encodes the point and the number to bytes
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
            if (verifyZKP(ecCurve, G, n, pointG1, zkpx1, PC_ID) ){
                System.out.println("ZKP x1 OK.");
            } else {
                System.out.println("ZKP x1 failed.");
            }
            if (verifyZKP(ecCurve, G, n, pointG2, zkpx2, PC_ID) ){
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
            if (verifyZKP(ecCurve, GA, n, A, zkpx2s, PC_ID) ){
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
