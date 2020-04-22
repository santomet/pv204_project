package applets;

import javacard.framework.*;
import javacard.security.*;
import javacardx.crypto.*;
//import opencrypto.jcmathlib.*;


import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.security.spec.EllipticCurve;

import org.bouncycastle.jce.ECNamedCurveTable;
import org.bouncycastle.jce.spec.ECParameterSpec;
import org.bouncycastle.jce.ECPointUtil;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.util.Arrays;

public class AlmostSecureApplet extends javacard.framework.Applet {
    
    
    // MAIN INSTRUCTION CLASS

    final static byte CLA_SIMPLEAPPLET = (byte) 0xB0;

    // INSTRUCTIONS
    final static byte INS_JPAKE1 = (byte) 0x01;
    final static byte INS_JPAKE3 = (byte) 0x02;
   
    
    final static byte INS_ENCRYPT = (byte) 0x50;
    final static byte INS_DECRYPT = (byte) 0x51;
    final static byte INS_SETKEY = (byte) 0x52;
    final static byte INS_HASH = (byte) 0x53;
    final static byte INS_RANDOM = (byte) 0x54;
    final static byte INS_VERIFYPIN = (byte) 0x55;
    final static byte INS_SETPIN = (byte) 0x56;
    final static byte INS_RETURNDATA = (byte) 0x57;
    final static byte INS_SIGNDATA = (byte) 0x58;
    
    final static short JPAKE1_G1_OFFSET_DATA = (short) 0x0;
    final static short JPAKE1_V1_OFFSET_DATA = (short) 0x21;
    final static short JPAKE1_r1_OFFSET_DATA = (short) 0x42;
    final static short JPAKE1_G2_OFFSET_DATA = (short) 0x62;
    final static short JPAKE1_V2_OFFSET_DATA = (short) 0x83;
    final static short JPAKE1_r2_OFFSET_DATA = (short) 0xA4;
    
    final static short JPAKE2_G3_OFFSET_DATA = (short) 0x0;
    final static short JPAKE2_V3_OFFSET_DATA = (short) 0x21;
    final static short JPAKE2_r3_OFFSET_DATA = (short) 0x42;
    final static short JPAKE2_G4_OFFSET_DATA = (short) 0x62;
    final static short JPAKE2_V4_OFFSET_DATA = (short) 0x83;
    final static short JPAKE2_r4_OFFSET_DATA = (short) 0xA4;
    
    final static short JPAKE3_A_OFFSET_DATA = (short) 0x0;
    final static short JPAKE3_Vx2s_OFFSET_DATA = (short) 0x21;
    final static short JPAKE3_rx2s_OFFSET_DATA = (short) 0x42;
    
    final static short JPAKE4_B_OFFSET_DATA = (short) 0x0;
    final static short JPAKE4_Vx4s_OFFSET_DATA = (short) 0x21;
    final static short JPAKE4_rx4s_OFFSET_DATA = (short) 0x42;
    
    final static short JPAKE1_TOTAL_DATASIZE = (short) 0xC4;
    final static short JPAKE2_TOTAL_DATASIZE = (short) 0xC4;
    final static short JPAKE3_TOTAL_DATASIZE = (short) 0x62;
    final static short JPAKE4_TOTAL_DATASIZE = (short) 0x62;
    
    final static short JPAKE_COMPRESSEDPOINTSIZE = (short) 0x21;
    final static short JPAKE_SCALARSIZE = (short) 0x20;

    final static short ARRAY_LENGTH = (short) 0xff;
    final static byte AES_BLOCK_LENGTH = (short) 0x16;

    final static short SW_BAD_TEST_DATA_LEN = (short) 0x6680;
    final static short SW_KEY_LENGTH_BAD = (short) 0x6715;
    final static short SW_CIPHER_DATA_LENGTH_BAD = (short) 0x6710;
    final static short SW_OBJECT_NOT_AVAILABLE = (short) 0x6711;
    final static short SW_BAD_PIN = (short) 0x6900;
    final static short SW_JPAKE1_PROOF_FAILED = (short) 0xA001;
    final static short SW_JPAKE3_PROOF_FAILED = (short) 0xA002;

    final static short SW_Exception = (short) 0xff01;
    final static short SW_ArrayIndexOutOfBoundsException = (short) 0xff02;
    final static short SW_ArithmeticException = (short) 0xff03;
    final static short SW_ArrayStoreException = (short) 0xff04;
    final static short SW_NullPointerException = (short) 0xff05;
    final static short SW_NegativeArraySizeException = (short) 0xff06;
    final static short SW_CryptoException_prefix = (short) 0xf100;
    final static short SW_SystemException_prefix = (short) 0xf200;
    final static short SW_PINException_prefix = (short) 0xf300;
    final static short SW_TransactionException_prefix = (short) 0xf400;
    final static short SW_CardRuntimeException_prefix = (short) 0xf500;

    private AESKey m_aesKey = null;
    private Cipher m_encryptCipher = null;
    private Cipher m_decryptCipher = null;
    private RandomData m_secureRandom = null;
    protected MessageDigest m_hash = null;
    private OwnerPIN m_pin = null;
    private byte[] m_rawpin = null;
    private Signature m_sign = null;
    private KeyPair m_keyPair = null;
    private Key m_privateKey = null;
    private Key m_publicKey = null;
    
    //EC and schnorr
    protected ECPoint         Gen = null; //generator point 
    protected ECPoint         G1 = null;
    protected ECPoint         G2 = null;
    protected ECPoint         G3 = null;
    protected ECPoint         G4 = null;
    protected ECPoint         GA = null;
    private BigInteger        n = null;
    private BigInteger        x4 = null;
    private AESKey            Ks = null; //AES session key
    
    protected ECParameterSpec   ecSpec = null;
    protected ECCurve.Fp        ecCurve = null;
    //schnorr
    byte[] mID = null;
    byte[] theirID = null;
    

    // TEMPORARRY ARRAY IN RAM
    private byte m_ramArray[] = null;
    // PERSISTENT ARRAY IN EEPROM
    private byte m_dataArray[] = null;

    /**
     * SimpleApplet default constructor Only this class's install method should
     * create the applet object.
     */
    protected AlmostSecureApplet(byte[] buffer, short offset, byte length) {
        // data offset is used for application specific parameter.
        // initialization with default offset (AID offset).
        short dataOffset = offset;
        boolean isOP2 = false;

        if (length > 9) {
            // Install parameter detail. Compliant with OP 2.0.1.

            // | size | content
            // |------|---------------------------
            // |  1   | [AID_Length]
            // | 5-16 | [AID_Bytes]
            // |  1   | [Privilege_Length]
            // | 1-n  | [Privilege_Bytes] (normally 1Byte)
            // |  1   | [Application_Proprietary_Length]
            // | 0-m  | [Application_Proprietary_Bytes]
            // shift to privilege offset
            dataOffset += (short) (1 + buffer[offset]);
            // finally shift to Application specific offset
            dataOffset += (short) (1 + buffer[dataOffset]);

            // go to proprietary data
            dataOffset++;

            m_dataArray = new byte[ARRAY_LENGTH];
            Util.arrayFillNonAtomic(m_dataArray, (short) 0, ARRAY_LENGTH, (byte) 0);

            // CREATE AES KEY OBJECT
            m_aesKey = (AESKey) KeyBuilder.buildKey(KeyBuilder.TYPE_AES, KeyBuilder.LENGTH_AES_256, false);
            // CREATE OBJECTS FOR CBC CIPHERING
            m_encryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);
            m_decryptCipher = Cipher.getInstance(Cipher.ALG_AES_BLOCK_128_CBC_NOPAD, false);

            // CREATE RANDOM DATA GENERATORS
            m_secureRandom = RandomData.getInstance(RandomData.ALG_SECURE_RANDOM);

            // TEMPORARY BUFFER USED FOR FAST OPERATION WITH MEMORY LOCATED IN RAM
            m_ramArray = JCSystem.makeTransientByteArray((short) 260, JCSystem.CLEAR_ON_DESELECT);

            // SET KEY VALUE
            m_aesKey.setKey(m_dataArray, (short) 0);

            // INIT CIPHERS WITH NEW KEY
            m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
            m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);

            m_pin = new OwnerPIN((byte) 5, (byte) 4); // 5 tries, 4 digits in pin
            m_pin.update(m_dataArray, (byte) 0, (byte) 4); // set initial random pin
            
            m_rawpin = new byte [] {0x01, 0x02, 0x03, 0x04};
            // CREATE RSA KEYS AND PAIR 
            m_keyPair = new KeyPair(KeyPair.ALG_RSA_CRT, KeyBuilder.LENGTH_RSA_2048);
            m_keyPair.genKeyPair(); // Generate fresh key pair on-card
            m_publicKey = m_keyPair.getPublic();
            m_privateKey = m_keyPair.getPrivate();
            // SIGNATURE ENGINE    
            m_sign = Signature.getInstance(Signature.ALG_RSA_SHA_PKCS1, false);
            // INIT WITH PRIVATE KEY
            m_sign.init(m_privateKey, Signature.MODE_SIGN);

            // INIT HASH ENGINE
            //m_hash = MessageDigest.getInstance(MessageDigest.ALG_SHA_256, false);

            // update flag
            isOP2 = true;
            
            //ECC
            ecSpec = ECNamedCurveTable.getParameterSpec("prime256v1");
            n = ecSpec.getN();
            
            ecCurve = (ECCurve.Fp) ecSpec.getCurve();
            Gen = ecSpec.getG();

            mID = new byte[]{'c', 'a', 'r', 'd'};
            theirID = new byte[]{'u', 's', 'e', 'r'};
           
        } 

        // register this instance
        register();
    }

    /**
     * Method installing the applet.
     *
     * @param bArray the array containing installation parameters
     * @param bOffset the starting offset in bArray
     * @param bLength the length in bytes of the data parameter in bArray
     */
    public static void install(byte[] bArray, short bOffset, byte bLength) throws ISOException {
        // applet  instance creation 
        new AlmostSecureApplet(bArray, bOffset, bLength);
    }

    /**
     * Select method returns true if applet selection is supported.
     *
     * @return boolean status of selection.
     */
    public boolean select() {
        clearSessionData();
        
        return true;
    }

    /**
     * Deselect method called by the system in the deselection process.
     */
    public void deselect() {
        clearSessionData();
    }

    /**
     * Method processing an incoming APDU.
     *
     * @see APDU
     * @param apdu the incoming APDU
     * @exception ISOException with the response bytes defined by ISO 7816-4
     */
    public void process(APDU apdu) throws ISOException {
        // get the buffer with incoming APDU
        byte[] apduBuffer = apdu.getBuffer();

        // ignore the applet select command dispached to the process
        if (selectingApplet()) {
            return;
        }

        try {
            // APDU instruction parser
            if (apduBuffer[ISO7816.OFFSET_CLA] == CLA_SIMPLEAPPLET) {
                switch (apduBuffer[ISO7816.OFFSET_INS]) {
                    case INS_JPAKE1:
                        JPake1(apdu);
                        break;
                    case INS_JPAKE3:
                        JPake3(apdu);
                        break;
                    case INS_SETKEY:
                        SetKey(apdu);
                        break;
                    case INS_ENCRYPT:
                        Encrypt(apdu);
                        break;
                    case INS_DECRYPT:
                        Decrypt(apdu);
                        break;
                    case INS_HASH:
                        Hash(apdu);
                        break;
                    case INS_RANDOM:
                        Random(apdu);
                        break;
                    case INS_VERIFYPIN:
                        VerifyPIN(apdu);
                        break;
                    case INS_SETPIN:
                        SetPIN(apdu);
                        break;
                    case INS_RETURNDATA:
                        ReturnData(apdu);
                        break;
                    case INS_SIGNDATA:
                        Sign(apdu);
                        break;
                    default:
                        // The INS code is not supported by the dispatcher
                        ISOException.throwIt(ISO7816.SW_INS_NOT_SUPPORTED);
                        break;
                }
            } else {
                ISOException.throwIt(ISO7816.SW_CLA_NOT_SUPPORTED);
            }

            // Capture all reasonable exceptions and change into readable ones (instead of 0x6f00) 
        } catch (ISOException e) {
            throw e; // Our exception from code, just re-emit
        } catch (ArrayIndexOutOfBoundsException e) {
            ISOException.throwIt(SW_ArrayIndexOutOfBoundsException);
        } catch (ArithmeticException e) {
            ISOException.throwIt(SW_ArithmeticException);
        } catch (ArrayStoreException e) {
            ISOException.throwIt(SW_ArrayStoreException);
        } catch (NullPointerException e) {
            ISOException.throwIt(SW_NullPointerException);
        } catch (NegativeArraySizeException e) {
            ISOException.throwIt(SW_NegativeArraySizeException);
        } catch (CryptoException e) {
            ISOException.throwIt((short) (SW_CryptoException_prefix | e.getReason()));
        } catch (SystemException e) {
            ISOException.throwIt((short) (SW_SystemException_prefix | e.getReason()));
        } catch (PINException e) {
            ISOException.throwIt((short) (SW_PINException_prefix | e.getReason()));
        } catch (TransactionException e) {
            ISOException.throwIt((short) (SW_TransactionException_prefix | e.getReason()));
        } catch (CardRuntimeException e) {
            ISOException.throwIt((short) (SW_CardRuntimeException_prefix | e.getReason()));
        } catch (Exception e) {
            ISOException.throwIt(SW_Exception);
        }
    }

    void clearSessionData() {
        // E.g., fill sesssion data in RAM with zeroes
        Util.arrayFillNonAtomic(m_ramArray, (short) 0, (short) m_ramArray.length, (byte) 0);
        
        // Or better fill with random data
        m_secureRandom.generateData(m_ramArray, (short) 0, (short) m_ramArray.length);
    }
    
    // SET ENCRYPTION & DECRYPTION KEY
    void SetKey(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH
        if ((short) (dataLen * 8) != KeyBuilder.LENGTH_AES_256) {
            ISOException.throwIt(SW_KEY_LENGTH_BAD);
        }

        // SET KEY VALUE
        m_aesKey.setKey(apdubuf, ISO7816.OFFSET_CDATA);

        // INIT CIPHERS WITH NEW KEY
        m_encryptCipher.init(m_aesKey, Cipher.MODE_ENCRYPT);
        m_decryptCipher.init(m_aesKey, Cipher.MODE_DECRYPT);
    }
    
    void jpakeBouncyTest(APDU apdu) {
        
    } 
    
    
    void JPake1(APDU apdu) {
        
        byte[] apdubuf = apdu.getBuffer();
        //short datalen = apdu.getIncomingLength();
        
        //CHEC IF INCOMING APDU HAS THE RIGHT LENGTH
        //if(datalen != JPAKE1_TOTAL_DATASIZE) {
          //  ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        //}
        
        short expectedDataLen = apdu.setIncomingAndReceive();
        // CHECK EXPECTED LENGTH 
        if (expectedDataLen != JPAKE2_TOTAL_DATASIZE) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }
        short inDataOffset = apdu.getOffsetCdata();
        short outDataOffset = apdu.getOffsetCdata();
                
        byte [] G1Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_G1_OFFSET_DATA, inDataOffset + JPAKE1_G1_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        G1 = ecCurve.decodePoint(G1Array);
        byte [] V1Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_V1_OFFSET_DATA, inDataOffset+ JPAKE1_V1_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        ECPoint V1 = ecCurve.decodePoint(V1Array);
        
        byte [] r1Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_r1_OFFSET_DATA, inDataOffset + JPAKE1_r1_OFFSET_DATA + JPAKE_SCALARSIZE);
        BigInteger  r1 = new BigInteger(1, r1Array);
        
        byte [] G2Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_G2_OFFSET_DATA, inDataOffset + JPAKE1_G2_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        G2 = ecCurve.decodePoint(G2Array); //savet this for later!!!
        byte [] V2Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_V2_OFFSET_DATA, inDataOffset + JPAKE1_V2_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        ECPoint V2 = ecCurve.decodePoint(V2Array);
        
        byte [] r2Array = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE1_r2_OFFSET_DATA, inDataOffset + JPAKE1_r2_OFFSET_DATA + JPAKE_SCALARSIZE);
        BigInteger  r2 = new BigInteger(1, r2Array);
        
        G1 = G1.normalize();
        G2 = G2.normalize();
        V1 = V1.normalize();
        V2 = V2.normalize();
        
        if (!verifyZKP(Gen, G1, V1, r1, theirID) || !verifyZKP(Gen, G2, V2, r2, theirID)) {
            //sheeeeit
            ISOException.throwIt(SW_JPAKE1_PROOF_FAILED);
        }

        
        BigInteger x3 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom());
    	x4 = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
    			n.subtract(BigInteger.ONE), new SecureRandom()); //save this for later
        
        G3 = Gen.multiply(x3);
        G4 = Gen.multiply(x4);
        
        G3 = G3.normalize();
        G4 = G4.normalize();
        
        byte [] G3BArray = G3.getEncoded(true);
        
        SchnorrZKP zkpG3 = new SchnorrZKP();
        SchnorrZKP zkpG4 = new SchnorrZKP();
        zkpG3.generateZKP(Gen, n, x3, G3, mID);
        zkpG4.generateZKP(Gen, n, x4, G4, mID);
        
        byte [] r3 = zkpG3.r.toByteArray();
        byte [] r4 = zkpG4.r.toByteArray();
        
        if(r3.length > 32) {
            r3 = Arrays.copyOfRange(r3, r3.length-32, r3.length);
        }
        if(r4.length > 32) {
            r4 = Arrays.copyOfRange(r4, r4.length-32, r4.length);
        }
        
        //Prepare JPAKE2 data
        Util.arrayCopyNonAtomic(G3.getEncoded(true), (short)0, apdubuf, (short)(JPAKE2_G3_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(zkpG3.V.getEncoded(true), (short)0, apdubuf, (short)(JPAKE2_V3_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(r3, (short)0, apdubuf, (short)(JPAKE2_r3_OFFSET_DATA + outDataOffset) , JPAKE_SCALARSIZE);
        Util.arrayCopyNonAtomic(G4.getEncoded(true), (short)0, apdubuf, (short)(JPAKE2_G4_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(zkpG4.V.getEncoded(true), (short)0, apdubuf, (short)(JPAKE2_V4_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(r4, (short)0, apdubuf, (short)(JPAKE2_r4_OFFSET_DATA + outDataOffset) , JPAKE_SCALARSIZE);
        
        apdu.setOutgoingAndSend(outDataOffset, expectedDataLen);

//STEP 2!!!!!
        
        //ALICESIM
//        ECPoint GA = X1.add(G3).add(G4); 
//    	ECPoint A = GA.multiply(x2.multiply(s).mod(n));
//				
//    	SchnorrZKP zkpX2s = new SchnorrZKP();
//    	zkpX2s.generateZKP(GA, n, x2.multiply(s).mod(n), A, theirID);
//        //-------------------
//        
//        ECPoint GB = X1.add(X2).add(G3); 
//    	ECPoint B = GB.multiply(x4.multiply(s).mod(n));
//				
//    	SchnorrZKP zkpX4s = new SchnorrZKP();
//    	zkpX4s.generateZKP(GB, n, x4.multiply(s).mod(n), B, mID);
//        
        
        //CHECK!!!
        //ALICESIM .
//        if (verifyZKP(GB, B, zkpX4s.getV(), zkpX4s.getr(), mID)) {
//            //ok this works
//            byte[] kkt = new byte[] {0x01};
//        }
//        //----------------------
//        
//        if (verifyZKP(GA, A, zkpX2s.getV(), zkpX2s.getr(), theirID)) {
//            //ok this works
//            byte[] kkt = new byte[] {0x01};
//        }
//        
//        
//        //ALICESIM
//        //opencrypto.jcmathlib.Integer Ka = new opencrypto.jcmathlib.Integer((short)64, ecc.bnh);
//        BigInteger Ka = getSHA256(B.subtract(G4.multiply(x2.multiply(s).mod(n))).multiply(x2).getXCoord().toBigInteger());
//        //-----------------------------
//        
//        //opencrypto.jcmathlib.Integer Kb = new opencrypto.jcmathlib.Integer((short)64, ecc.bnh);
//        BigInteger Kb = getSHA256( A.subtract(X2.multiply(x4.multiply(s).mod(n))).multiply(x4).getXCoord().toBigInteger());
//        
//        if(Ka.compareTo(Kb) == 0) {
//            //WE WON
//            byte[] kkt = new byte[] {0x01};
//        }
        
    }
    
    
    void JPake3(APDU apdu) {
        byte [] apdubuf = apdu.getBuffer();
        short expectedDataLen = apdu.setIncomingAndReceive();
        // CHECK EXPECTED LENGTH 
        if (expectedDataLen != JPAKE4_TOTAL_DATASIZE) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }
        short inDataOffset = apdu.getOffsetCdata();
        short outDataOffset = apdu.getOffsetCdata();
        
        GA = G1.add(G3).add(G4); //save for later
        
        byte [] AArray = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE3_A_OFFSET_DATA, inDataOffset + JPAKE3_A_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        ECPoint A = ecCurve.decodePoint(AArray);
        byte [] Vx2sArray = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE3_Vx2s_OFFSET_DATA, inDataOffset + JPAKE3_Vx2s_OFFSET_DATA + JPAKE_COMPRESSEDPOINTSIZE);
        ECPoint Vx2s = ecCurve.decodePoint(Vx2sArray);
        
        byte [] rx2sArray = Arrays.copyOfRange(apdubuf, inDataOffset + JPAKE3_rx2s_OFFSET_DATA, inDataOffset + JPAKE3_rx2s_OFFSET_DATA + JPAKE_SCALARSIZE);
        BigInteger  rx2s = new BigInteger(1, rx2sArray);
        
        GA = GA.normalize();
        A = A.normalize();
        Vx2s = Vx2s.normalize();
        
        if (!verifyZKP(GA, A, Vx2s, rx2s, theirID)) {
            //sheeeeeeeeit
            ISOException.throwIt(SW_JPAKE3_PROOF_FAILED);
        }
        
        BigInteger s = org.bouncycastle.util.BigIntegers.fromUnsignedByteArray(m_rawpin);
        
        BigInteger scal = x4.multiply(s).mod(n);
        ECPoint Kcurve = G2.multiply(scal);
        Kcurve = A.subtract(Kcurve);
        Kcurve = Kcurve.multiply(x4);
        
        Kcurve = Kcurve.normalize();
        
        BigInteger K = Kcurve.getXCoord().toBigInteger();
        
        byte [] Karr = K.toByteArray();
        
        
        if(Karr.length > 32) {
            Karr = Arrays.copyOfRange(Karr, Karr.length-32, Karr.length);
        }
        
      //  Ks.setKey(Karr, (short) 32);
        
        
        ECPoint GB = G1.add(G2).add(G3);
        GB = GB.normalize();
    	ECPoint B = GB.multiply(x4.multiply(s).mod(n));
        B = B.normalize();

    	SchnorrZKP zkpG4s = new SchnorrZKP();
    	zkpG4s.generateZKP(GB, n, x4.multiply(s).mod(n), B, mID);
        
        byte [] rx4s = zkpG4s.r.toByteArray();
        
        if(rx4s.length > 32) {
            rx4s = Arrays.copyOfRange(rx4s, rx4s.length-32, rx4s.length);
        }
        
        Util.arrayCopyNonAtomic(B.getEncoded(true), (short)0, apdubuf, (short)(JPAKE4_B_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(zkpG4s.V.getEncoded(true), (short)0, apdubuf, (short)(JPAKE4_Vx4s_OFFSET_DATA + outDataOffset) , JPAKE_COMPRESSEDPOINTSIZE);
        Util.arrayCopyNonAtomic(rx4s, (short)0, apdubuf, (short)(JPAKE4_rx4s_OFFSET_DATA + outDataOffset) , JPAKE_SCALARSIZE);
        
        apdu.setOutgoingAndSend(outDataOffset, expectedDataLen);

//        System.out.println("CARD:     --");
//        System.out.println(Kcurve + " KCurve");
//        System.out.println(K + " key");
//        System.out.println(G1 + " G1");
//        System.out.println(G2 + " G2");
//        System.out.println(G3 + " G3");
//        System.out.println(G4 + " G4");
//        
//        System.out.println(A + " A");
//        System.out.println(B + " B");
//        System.out.println(GA + " GA");
//        System.out.println(GB + " GB");
//        System.out.println(Vx2s + " Vx2s");
//        System.out.println(rx2s + " rx2s");
//        System.out.println(s + " s");
        
    }

    // ENCRYPT INCOMING BUFFER
    void Encrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_encryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        // NOTE: In-place encryption directly with apdubuf as output can be performed. m_ramArray used to demonstrate Util.arrayCopyNonAtomic

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // DECRYPT INCOMING BUFFER
    void Decrypt(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // CHECK EXPECTED LENGTH (MULTIPLY OF AES BLOCK LENGTH)
        if ((dataLen % 16) != 0) {
            ISOException.throwIt(SW_CIPHER_DATA_LENGTH_BAD);
        }

        // ENCRYPT INCOMING BUFFER
        m_decryptCipher.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, dataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    // HASH INCOMING BUFFER
    void Hash(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        if (m_hash != null) {
         //   m_hash.doFinal(apdubuf, ISO7816.OFFSET_CDATA, dataLen, m_ramArray, (short) 0);
        } else {
            ISOException.throwIt(SW_OBJECT_NOT_AVAILABLE);
        }

        // COPY ENCRYPTED DATA INTO OUTGOING BUFFER
        //Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, m_hash.getLength());

        // SEND OUTGOING BUFFER
     //   apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, m_hash.getLength());
    }

    // GENERATE RANDOM DATA
    void Random(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();

        // GENERATE DATA
        short randomDataLen = apdubuf[ISO7816.OFFSET_P1];
        m_secureRandom.generateData(apdubuf, ISO7816.OFFSET_CDATA, randomDataLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, randomDataLen);
    }

    // VERIFY PIN
    void VerifyPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // VERIFY PIN
        if (m_pin.check(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen) == false) {
            ISOException.throwIt(SW_BAD_PIN);
        }
    }

    // SET PIN 
    // Be aware - this method will allow attacker to set own PIN - need to protected. 
    // E.g., by additional Admin PIN or all secret data of previous user needs to be reased 
    void SetPIN(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        // SET NEW PIN
        m_pin.update(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen);
    }

    // RETURN INPU DATA UNCHANGED
    void ReturnData(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();

        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, dataLen);
    }

    void Sign(APDU apdu) {
        byte[] apdubuf = apdu.getBuffer();
        short dataLen = apdu.setIncomingAndReceive();
        short signLen = 0;

        // SIGN INCOMING BUFFER
        signLen = m_sign.sign(apdubuf, ISO7816.OFFSET_CDATA, (byte) dataLen, m_ramArray, (byte) 0);

        // COPY SIGNED DATA INTO OUTGOING BUFFER
        Util.arrayCopyNonAtomic(m_ramArray, (short) 0, apdubuf, ISO7816.OFFSET_CDATA, signLen);

        // SEND OUTGOING BUFFER
        apdu.setOutgoingAndSend(ISO7816.OFFSET_CDATA, signLen);
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
    
    
        public BigInteger getSHA256(ECPoint generator, ECPoint V, ECPoint X, byte[] userID) {

    	MessageDigest sha256 = null;

    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		
    		byte [] GBytes = generator.getEncoded(true);
    		byte [] VBytes = V.getEncoded(true);
    		byte [] XBytes = X.getEncoded(true);
    		
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

    public BigInteger getSHA256(BigInteger K) {

    	MessageDigest sha256 = null;

    	try {
    		sha256 = MessageDigest.getInstance("SHA-256");
    		sha256.update(K.toByteArray());
    	} catch (Exception e) {
    		e.printStackTrace();
    	}

    	return new BigInteger(1, sha256.digest()); // 1 for positive int
    }
    
    private class SchnorrZKP {
    	
    	private ECPoint V = null;
    	private BigInteger r = null;
    			
    	private SchnorrZKP () {
    		// constructor
    	}
    	
    	private void generateZKP (ECPoint generator, BigInteger n, BigInteger x, ECPoint X, byte[] userID) {

        	/* Generate a random v from [1, n-1], and compute V = G*v */
        	BigInteger v = org.bouncycastle.util.BigIntegers.createRandomInRange(BigInteger.ONE, 
        			n.subtract(BigInteger.ONE), new SecureRandom());
        	V = generator.multiply(v);
        	
        	BigInteger h = getSHA256(generator, V, X, userID); // h

        	r = v.subtract(x.multiply(h)).mod(n); // r = v-x*h mod n   
        }
    	
    	private ECPoint getV() {
    		return V;
    	}
    	
    	private BigInteger getr() {
    		return r;
    	}
    	
    }
}

