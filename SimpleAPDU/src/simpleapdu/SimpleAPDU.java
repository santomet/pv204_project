package simpleapdu;

import applets.AlmostSecureApplet;
import cardTools.CardManager;
import cardTools.RunConfig;
import cardTools.Util;

import javax.smartcardio.CommandAPDU;
import javax.smartcardio.ResponseAPDU;

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

    /**
     * Main entry point.
     *
     * @param args
     */
    public static void main(String[] args) {
        try {
            SimpleAPDU main = new SimpleAPDU();
            
            main.demoGetRandomDataCommand();
           //main.demoEncryptDecrypt();
           // main.demoUseRealCard();
            
                 
        } catch (Exception ex) {
            System.out.println("Exception : " + ex);
        }
    }

    public void demoGetRandomDataCommand() throws Exception {
        // CardManager abstracts from real or simulated card, provide with applet AID
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);          
        
        // Get default configuration for subsequent connection to card (personalized later)
        final RunConfig runCfg = RunConfig.getDefaultConfig();

        // A) If running on physical card
        // runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

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
        final ResponseAPDU response = cardMngr.transmit(new CommandAPDU(Util.hexStringToByteArray(STR_APDU_GETRANDOM)));
        byte[] data = response.getData();
        
        final ResponseAPDU response2 = cardMngr.transmit(new CommandAPDU(0xB0, 0x54, 0x00, 0x00, data)); // Use other constructor for CommandAPDU
        
        System.out.println(response);
    }

    public void demoEncryptDecrypt() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        //runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card
        runCfg.setAppletToSimulate(AlmostSecureApplet.class); 
        runCfg.setTestCardType(RunConfig.CARD_TYPE.JCARDSIMLOCAL); // Use local simulator

        // Connect to first available card
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        
        // Task 1
        // TODO: Prepare and send APDU with 32 bytes of data for encryption, observe output

        // Task 2
        // TODO: Extract the encrypted data from the card's response. Send APDU with this data for decryption
        // TODO: Compare match between data for encryption and decrypted data
        
        // Task 3
        // TODO: What is the value of AES key used inside applet? Use debugger to figure this out

        // Task 4
        // TODO: Prepare and send APDU for setting different AES key, then encrypt and verify (with http://extranet.cryptomathic.com/aescalc/index
    }    
    
    public void demoUseRealCard() throws Exception {
        final CardManager cardMngr = new CardManager(true, APPLET_AID_BYTE);
        final RunConfig runCfg = RunConfig.getDefaultConfig();
        runCfg.setTestCardType(RunConfig.CARD_TYPE.PHYSICAL); // Use real card

        // Connect to first available card
        System.out.print("Connecting to card...");
        if (!cardMngr.Connect(runCfg)) {
            System.out.println(" Failed.");
        }
        System.out.println(" Done.");

        // Task 5 
        // TODO: Obtain random data from real card

        // Task 6 
        // TODO: Set new key value and encrypt on card
        
        cardMngr.Disconnect(true);
    }    
}
