package simpleapdu;

import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.test.FixedSecureRandom.BigInteger;

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
    
    private static final Integer BIGINT_LENGTH = 33; 
    private static final Integer POINT_LENGTH = 33;
    private static final boolean COMPRESS_POINTS = true;
    private static final Integer ZKP_LENGTH = BIGINT_LENGTH + POINT_LENGTH;
    
    private static final byte[] PIN = {0x01, 0x02, 0x03, 0x04};
    private static final BigInteger SHARED_BIG_INT = BigIntegers.fromUnsignedByteArray(PIN);
    private static final String CARD_ID = "Card ID";
    private static final String PC_ID = "PC ID";
    
    private static ECParameterSpec ecSpec = ECNamedCurveTable.getParameterSpec("secp256r1");
    private static ECCurve ecCurve = ecSpec.getCurve();
    private static ECPoint G = ecSpec.getG();
    private static BigInteger q = ecSpec.getCurve().getCofactor();
    private static BigInteger n = ecSpec.getN();

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            jpakeWithoutCard();
                 
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void jpakeWithoutCard() {
        AlmostCard card = new AlmostCard();
        
        /* get random x1, x2 from [1, n-1] */
        BigInteger x1 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	BigInteger x2 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	
        /* compute G x [x1], G x [x2] */
        ECPoint pointG1 = G.multiply(x1);
        ECPoint pointG2 = G.multiply(x2);
        
        /* create ZKP of x1 and x2 (Schnorr) */
        SchnorrZKP zkpx1 = generateZKP(G, n, x1, pointG1, PC_ID);
        SchnorrZKP zkpx2 = generateZKP(G, n, x2, pointG2, PC_ID);

        /* Encode pointG1, pointG2, zkpx1, zkpx2 */
        byte[] apduData1 = jpakeFirstApdu(pointG1, pointG2, zkpx1, zkpx2);
        
        /* Send data to card and get the response */
        byte[] response = card.processJPAKE(apduData1);
        
        /* Parse the response */
        ByteArrayInputStream stream = new ByteArrayInputStream(response);
        byte[] pointBytes = new byte[POINT_LENGTH];
        byte[] zkpBytes = new byte[ZKP_LENGTH];
        
        /* Get G3 = G x [x3], and a ZKP of x3 */
        stream.read(pointBytes, 0, POINT_LENGTH);
        ECPoint pointG3 = ecCurve.decodePoint(pointBytes);
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx3 = new SchnorrZKP(zkpBytes);
        
        /* Get G4 = G x [x4], and a ZKP of x4 */
        stream.read(pointBytes, 0, POINT_LENGTH);
        ECPoint pointG4 = ecCurve.decodePoint(pointBytes);    
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx4 = new SchnorrZKP(zkpBytes);
        
        /* Compute GB = G1 + G2 + G3 */
        ECPoint GB = pointG1.add(pointG2).add(pointG3);
        
        /* Get B = (G1 + G2 + G3) x [x4*s] and a ZKP for x4*s */
        stream.read(pointBytes, 0, POINT_LENGTH);
        ECPoint B = ecCurve.decodePoint(pointBytes);
        stream.read(zkpBytes, 0, ZKP_LENGTH);
        SchnorrZKP zkpx4s = new SchnorrZKP(zkpBytes);
        
            
        /* Verify ZKP of x3, x4, and x4*s */
        if (verifyZKP(ecCurve, G, n, pointG3, zkpx3, CARD_ID) ){
            System.out.println("ZKP x3 OK.");
        } else {
            System.out.println("ZKP x3 failed.");
        }
        if (verifyZKP(ecCurve, G, n, pointG4, zkpx4, CARD_ID) ){
            System.out.println("ZKP x4 OK.");
        } else {
            System.out.println("ZKP x4 failed.");
        }
         if (verifyZKP(ecCurve, GB, n, B, zkpx4s, CARD_ID) ){
            System.out.println("ZKP x4*s OK.");
        } else {
            System.out.println("ZKP x4*s failed.");
        }

        /* Compute GA = G1 + G3 + G4 */
        ECPoint GA = pointG1.add(pointG3).add(pointG4).normalize(); 
    	
        /* Compute A = (G1 + G3 + G4) x [x2*s] and a ZKP for x2*s */
        ECPoint A = GA.multiply(x2.multiply(SHARED_BIG_INT).mod(n));				
    	SchnorrZKP zkpx2s = generateZKP(GA, n, x2.multiply(SHARED_BIG_INT).mod(n), A, PC_ID);
		
        /* Encode A and zkpx2s and send data to card */
        byte[] apduData2 = jpakeSecondApdu(A, zkpx2s);
        card.processJPAKE2(apduData2);
        
        /* Computed K = (B - (G4 x [x2*s])) x [x2] to get a shared secret */
        ECPoint pointK = B.subtract(pointG4.multiply(x2.multiply(SHARED_BIG_INT))).multiply(x2).normalize();
        BigInteger key = getSHA256(pointK.normalize().getXCoord().toBigInteger());
        
        /* Check if card has the same result */
        card.compareResultJPAKE(key);
    }
    
    public byte[] toByteWithoutSign(BigInteger bigInt) {
        // Not used now
        // removes first byte from BigInteger byte representation
        byte[] array = bigInt.toByteArray();
        byte[] tmp = new byte[array.length - 1];
        System.arraycopy(array, 1, tmp, 0, tmp.length);
        array = tmp;
        return array;
    }
    
    /*
        Encodes data for first APDU in JPAKE
    */
    public byte[] jpakeFirstApdu(ECPoint pointG1, ECPoint pointG2, SchnorrZKP zkpx1,SchnorrZKP zkpx2) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(pointG1.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx1.toByteArray());
        
        byteStream.write(pointG2.getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2.toByteArray());
                
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }

    /*
        Encodes data for second APDU in JPAKE
    */
    public byte[] jpakeSecondApdu(ECPoint A, SchnorrZKP zkpx2s) throws IOException {
        ByteArrayOutputStream byteStream = new ByteArrayOutputStream();
        
        byteStream.write(A.normalize().getEncoded(COMPRESS_POINTS));
        byteStream.write(zkpx2s.toByteArray());
        
        byte[] apduData = byteStream.toByteArray();
        byteStream.close();
        return apduData;
    }
    
    public BigInteger getSHA256(ECPoint G, ECPoint V, ECPoint D, String userID) {
    	MessageDigest sha256 = null;
    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		
    		byte[] GBytes = G.getEncoded(false);
    		byte[] VBytes = V.getEncoded(false);
    		byte[] XBytes = D.getEncoded(false);
    		byte[] userIDBytes = userID.getBytes();
    		
    		// It's good practice to prepend each item with a 4-byte length
    		sha256.update(ByteBuffer.allocate(4).putInt(GBytes.length).array());
    		sha256.update(GBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(VBytes.length).array());
    		sha256.update(VBytes);

    		sha256.update(ByteBuffer.allocate(4).putInt(XBytes.length).array());
    		sha256.update(XBytes);
    		
    		sha256.update(ByteBuffer.allocate(4).putInt(userIDBytes.length).array());
    		sha256.update(userIDBytes);    	
   		
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return new BigInteger(sha256.digest());
    }
    
    public BigInteger getSHA256(BigInteger toHash) {
    	MessageDigest sha256 = null;
    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		sha256.update(toHash.toByteArray());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}
    	return new BigInteger(1, sha256.digest()); // 1 for positive int
    }
    
    private SchnorrZKP generateZKP (ECPoint G, BigInteger n, BigInteger d, ECPoint D, String userID) {
            /* Generate a proof of knowledge of scalar for D = [d] x G */
            
            /* Generate a random v from [1, n-1], and compute V = [v] x G */
            BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
       			n.subtract(BigInteger.ONE), new SecureRandom());
            ECPoint V = G.multiply(v);
                
            BigInteger c = getSHA256(G, V, D, userID); // compute hash H(G || V || D || UserID)
            BigInteger r = v.subtract(d.multiply(c)).mod(n); // r = v-d*c mod n 
            return new SchnorrZKP(V,r);
    }
    
    private boolean verifyZKP(ECCurve ecCurve, ECPoint G, BigInteger n, ECPoint D, SchnorrZKP zkp, String userID) {
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
            int diff = BIGINT_LENGTH - this.getr().toByteArray().length;
            if (diff > 0){
                byteStream.write(new byte[diff]);
            }
            byteStream.write(this.getr().toByteArray());
            byte[] retBytes = byteStream.toByteArray();
            byteStream.close();
            return retBytes;
        }
    }
    
    
    
    private static class AlmostCard {
        private BigInteger x3 = null;
        private BigInteger x4 = null;
        private BigInteger key = null; 
        private ECPoint pointG1 = null;    	
        private ECPoint pointG2 = null;
        private ECPoint pointG3 = null;    	
        private ECPoint pointG4 = null;
        private ECPoint pointK = null;
        
        private boolean compareResultJPAKE(BigInteger otherKey){
            /* Returns true if this.key == other.key */
            if (this.key.equals(otherKey)) {
                System.out.println("They shared a key.");
                return true;
            } else {
                System.out.println("The key is not the same");
                return false;
            }
        }
        
        byte[] processJPAKE(byte[] inApdu) throws IOException {
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
        
        void processJPAKE2(byte[] inApdu) throws IOException {
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
