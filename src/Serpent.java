import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.lang.Integer;

public class Serpent implements BlockCipher {

    private int keySize;
    private byte[] key;
    private long[] prekeys;

    public Serpent() {
        prekeys = new long[140];
    }

    /**
     * Returns this block cipher's block size in bytes.
     *
     * @return  Block size.
     */
    public int blockSize() {
        return 16;
    }

    /**
     * Returns this block cipher's key size in bytes.
     *
     * @return  Key size.
     */
    public int keySize() {
        return 32;
    }

    /**
     * Set the key for this block cipher. If <TT>key</TT> is an array of bytes
     * whose length is less than <TT>keySize()</TT>, it will be padded to 
     * <TT>keySize()</TT>
     *
     * @param  key  Key.
     */
    public void setKey(byte[] key) {
        if (key.length != keySize()) {
            this.key = new byte[keySize()];
            for( int i = 0; i < key.length; i++ ) {
                this.key[i] = key[i];
            }
            for( int i = key.length; i < keySize(); i++ ) {
                if( i == key.length ) {
                    //Start of padding!
                    this.key[i] = (byte)0x80;
                }else {
                    this.key[i] = (byte)0x00;
                }
            }
        }else {
            this.key = key;
        }

        //prekey initialization from K
        for(int i = 0; i < 8; i++) {
            prekeys[i] = Packing.packLongLittleEndian(new byte[]{this.key[4*i],this.key[4*i+1],this.key[4*i+2],this.key[4*i+3],
                0x00, 0x00, 0x00, 0x00}, 0);
            //System.out.println("Prekey " + i + ": " + Hex.toString(new byte[]{this.key[4*i],this.key[4*i+1],this.key[4*i+2],this.key[4*i+3],
            //    0x00, 0x00, 0x00, 0x00}));
        }
        //Build out prekey array
        for( int i = 8; i < prekeys.length; i++ ) {
            ByteBuffer help = ByteBuffer.allocate(Integer.SIZE);
            help.putLong((long)i);
            help.order(ByteOrder.LITTLE_ENDIAN);
            long valI = help.getLong();
            help.order(ByteOrder.BIG_ENDIAN);
            help.putLong((long)0x9e3779b9);
            help.order(ByteOrder.LITTLE_ENDIAN);
            long phi = help.getLong();
            //(x << n) | (x >>> (32 - n)) Rotate
            prekeys[i] = prekeys[i-8] ^ prekeys[i-5] ^ prekeys[i-3] ^ prekeys[i-1] ^ 
                valI ^ phi;
            prekeys[i] = (prekeys[i] << 11) | (prekeys[i] >>> (21));
            //System.out.println("Prekey " + i + ": " + prekeys[i]);
        }

    }

    /**
     * Encrypt the given plaintext. <TT>text</TT> must be an array of bytes
     * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
     * contains the plaintext block. The plaintext block is encrypted using the
     * key specified in the most recent call to <TT>setKey()</TT>. On output,
     * <TT>text</TT> contains the ciphertext block.
     *
     * @param  text  Plaintext (on input), ciphertext (on output).
     */
    public void encrypt(byte[] text) {
        text = initPermutation(text);
        byte[] roundKey = new byte[16];
        //32 rounds
        for(int i = 0; i < 32; i++){
            roundKey = getRoundKey(i);
            for(int n = 0; n < 16; n++){
                text[n] = text[n] ^ roundKey[n];
            }
            text = sBox(text, i);
            text = linearTransform(text);
        }
        roundKey = getRoundKey(32);
        for(int n = 0; n < 16; n++){
            text[n] = text[n] ^ roundKey[n];
        }
        text = finalPermutation(text);
    }


    private byte[] initPermutation(byte[] data) {
        byte[] output = new byte[16];
        for (int i = 0;  i < 128; i++) {
            int bit = (input[(ipTable[i] & 0x7F) / 8] >>> ((ipTable[i] & 0x7F) % 8)) & 0x01;
            if ((bit & 0x01) == 1)
                output[i / 8] |= 1 << (i % 32);
            else
                output[i / 8] &= ~(1 << (i % 32));
        }
        return output; 
        
    }

    private byte[] finalPermutation(byte[] data) {
        byte[] output = new byte[16];
        for (int i = 0;  i < 128; i++) {
            int bit = (input[(fpTable[i] & 0x7F) / 8] >>> ((fpTable[i] & 0x7F) % 8)) & 0x01;
            if ((bit & 0x01) == 1)
                output[i / 8] |= 1 << (i % 32);
            else
                output[i / 8] &= ~(1 << (i % 32));
        }
        return output; 
    }

    private static byte[] s0 = new byte[]
        {3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12};
    private static byte[] s1 = new byte[]
        {15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4};
    private static byte[] s2 = new byte[]
        {8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2};
    private static byte[] s3 = new byte[]
        {0,15,11,8,12,9,6,3,13,1,2,4,10,7,5,14};
    private static byte[] s4 = new byte[]
        {1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13};
    private static byte[] s5 = new byte[]
        {15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1};
    private static byte[] s6 = new byte[]
        {7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0};
    private static byte[] s7 = new byte[]
        {1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6};
    private static byte[][] sBoxes = new byte[][]
        {s0,s1,s2,s3,s4,s5,s6,s7};

    private static byte[] ipTable = new byte[] {
         0, 32, 64,  96,  1, 33, 65,  97,  2, 34, 66,  98,  3, 35, 67,  99,
         4, 36, 68, 100,  5, 37, 69, 101,  6, 38, 70, 102,  7, 39, 71, 103,
         8, 40, 72, 104,  9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
        12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
        16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
        20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
        24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
        28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127
    };

    private static byte[] fpTable = new byte[] {
         0,  4,  8, 12, 16, 20, 24, 28, 32,  36,  40,  44,  48,  52,  56,  60,
        64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
         1,  5,  9, 13, 17, 21, 25, 29, 33,  37,  41,  45,  49,  53,  57,  61,
        65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
         2,  6, 10, 14, 18, 22, 26, 30, 34,  38,  42,  46,  50,  54,  58,  62,
        66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
         3,  7, 11, 15, 19, 23, 27, 31, 35,  39,  43,  47,  51,  55,  59,  63,
        67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127
    };

    /**
     * Perform S-Box manipulation to the given byte array of <TT>blocksize()</TT> length.
     *
     * @param data Input bit sequence
     * @param round Number of the current round, used to determine which S-Box to use.
     */
    private byte[] sBox(byte[] data, int round) {
        byte[] toUse = sBoxes[round%8];
        byte[] output = new byte[blockSize()];
        for( int i = 0; i < blockSize(); i++ ) {
            //Break signed-ness
            int curr = data[i]&0xFF;
            byte low4 = (byte)(curr>>>4);
            byte high4 = (byte)(curr&0x0F);
            output[i] = (toUse[low4]<<4) ^ (toUse[high4]);
        }
        return output;
    }
    
    /**
     * Performs linear transformation on the input bit sequence
     * 
     * @param data Input bit sequence
     * @return output bit sequence
     */
    private byte[] linearTransform(byte[] data){
    	byte[] output = new byte[blockSize()];
    	ByteBuffer buffer = ByteBuffer.wrap(data);
    	int x0 =  buffer.getInt();
    	int x1 =  buffer.getInt();
    	int x2 =  buffer.getInt();
    	int x3 =  buffer.getInt();
    	//shift left 13 times
    	x0 = (x0 << 13) | (x0 >>> (19));			//wrote these out so you knew what I was doing
    	x2 = (x2 << 3) | (x2 >>> (32 - 3));
    	x1 = x1 ^ x0 ^ x2;
    	x3 = x3 ^ x2 ^ ((x0 << 3) | (x0 >>> (32 - 3)));
    	x1 = (x1 << 1) | (x1 >>> (32 - 1));
    	x3 = (x3 << 1) | (x3 >>> (32 - 7));
    	x0 = x0 ^ x1 ^ x3;
    	x2 = x2 ^ x3 ^ ((x1 << 7) | (x1 >>> (32 - 7)));
    	x0 = (x0 << 5) | (x0 >>> (32-5));
    	x2 = (x2 << 22) | (x2 >>> (32-22));
    	buffer.putInt(x0);			//I'm not sure on the order here, could be backwards?
    	buffer.putInt(x1);
    	buffer.putInt(x2);
    	buffer.putInt(x3);
    	output = buffer.array();
    	return output;
    }
    private byte[] getRoundKey(int round) {
        byte[] k0 = new byte[8];
        Packing.unpackLongLittleEndian( prekeys,4*round,k0,0,1 );
        byte[] k1 = new byte[8];
        Packing.unpackLongLittleEndian( prekeys,4*round+1,k1,0,1 );
        byte[] k2 = new byte[8];
        Packing.unpackLongLittleEndian( prekeys,4*round+2,k2,0,1 );
        byte[] k3 = new byte[8];
        Packing.unpackLongLittleEndian( prekeys,4*round+3,k3,0,1 );

        byte[] k = new byte[16];
        k[0] = k0[0];				//changed declaration to make compiler happy
        k[1] = k0[1];
        k[2] = k0[2];
        k[3] = k0[3];
        k[4] = k1[0];
        k[5] = k1[1];
        k[6] = k1[2];
        k[7] = k1[3];
        k[8] = k2[0];
        k[9] = k2[1];
        k[10] = k2[2];
        k[11] = k2[3];
        k[12] = k3[0];
        k[13] = k3[1];
        k[14] = k3[2];
        k[15] = k3[3];
        //previuos declaration
       // {k0[0],k0[1],k0[2],k0[3],k1[0],k1[1],k1[2],k1[3],
       //     k2[0],k2[1],k2[2],k2[3],k3[0],k3[1],k3[2],k3[3]};
        return sBox(k,(3-round)%8);
    }

    /**
     * Main function, sets an all-zero-byte key, performs N encryptions of an all-zero-byte plaintext block
     * N specified in args
     */
    public static void main( String[] args ) {
        Serpent serpent = new Serpent();
        byte[] test_in = new byte[] {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        byte[] test_key = new byte[] {
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
        };
        int iters = Integer.parseInt(args[0]);
        for(int n = 0; n < iters; n++){
            serpent.setKey(test_key);
            serpent.encrypt(test_in);
        }
        //sBoxTest();
        //setKeyTest();
    }

    private static void setKeyTest() {
        Serpent serpent = new Serpent();

        byte[] test3 = new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        serpent.setKey( test3 );
        System.out.println("Test key: " + Hex.toString(test3));
        System.out.println("Round 0 : " + Hex.toString(serpent.getRoundKey(0)));
        System.out.println("Round 1 : " + Hex.toString(serpent.getRoundKey(1)));
        System.out.println("Round 2 : " + Hex.toString(serpent.getRoundKey(2)));
        System.out.println("Round 3 : " + Hex.toString(serpent.getRoundKey(3)));

        byte[] test4 = new byte[] {0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
            0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00};
        serpent.setKey( test4 );
        System.out.println("Test key: " + Hex.toString(test4));
        System.out.println("Round 0 : " + Hex.toString(serpent.getRoundKey(0)));
        System.out.println("Round 1 : " + Hex.toString(serpent.getRoundKey(1)));
        System.out.println("Round 2 : " + Hex.toString(serpent.getRoundKey(2)));
        System.out.println("Round 3 : " + Hex.toString(serpent.getRoundKey(3)));

        byte[] test1 = new byte[] {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF};
        serpent.setKey( test1 );
        System.out.println("Testing key setting and round key generation.");
        System.out.println("Test key: " + Hex.toString(test1));
        System.out.println("Round 0 : " + Hex.toString(serpent.getRoundKey(0)));
        System.out.println("Round 1 : " + Hex.toString(serpent.getRoundKey(1)));
        System.out.println("Round 2 : " + Hex.toString(serpent.getRoundKey(2)));
        System.out.println("Round 3 : " + Hex.toString(serpent.getRoundKey(3)));

        byte[] test2 = new byte[] {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF,
            0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF};
        serpent.setKey( test2 );
        System.out.println("Test key: " + Hex.toString(test2));
        System.out.println("Round 0 : " + Hex.toString(serpent.getRoundKey(0)));
        System.out.println("Round 1 : " + Hex.toString(serpent.getRoundKey(1)));
        System.out.println("Round 2 : " + Hex.toString(serpent.getRoundKey(2)));
        System.out.println("Round 3 : " + Hex.toString(serpent.getRoundKey(3)));
    }

    private static void sBoxTest(){
        Serpent serpent = new Serpent();
        byte[] test0 = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        byte[] test1 = new byte[] {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF};
        byte[] test2 = new byte[] {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
        byte[] test3 = new byte[] {0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10};
        System.out.println( Hex.toString(test0) );
        System.out.println( Hex.toString(serpent.sBox(test0,0)) );
        System.out.println( Hex.toString(test1) );
        System.out.println( Hex.toString(serpent.sBox(test1,0)) );
        System.out.println( Hex.toString(test2) );
        System.out.println( Hex.toString(serpent.sBox(test2,0)) );
        System.out.println( Hex.toString(test3) );
        System.out.println( Hex.toString(serpent.sBox(test3,0)) );
    }
}//Serpent.java


