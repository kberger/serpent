import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.lang.Integer;
import java.io.*;

public class Serpent implements BlockCipher {

    private static final byte xFF = (byte)0xFF;
	private int keySize;
    private byte[] key;
    private int[] prekeys;

    public Serpent() {
        prekeys = new int[140];
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
            prekeys[i] = Packing.packIntBigEndian(new byte[]{this.key[4*i],this.key[4*i+1],this.key[4*i+2],this.key[4*i+3]}, 0);
      //      System.out.println("Prekey " + i + ": " + prekeys[i]);
        }
        //Build out prekey array
        for( int i = 8; i < prekeys.length; i++ ) {
//            ByteBuffer help = ByteBuffer.allocate(Integer.SIZE);
//            help.order(ByteOrder.LITTLE_ENDIAN);
//            help.putInt(i-8);
//            int valI = help.getInt(0);
            byte[] prnt = new byte[4];
//            Packing.unpackIntBigEndian(valI, prnt, 0);
//            System.out.println("Int " + i + ": " + Hex.toString(prnt));

            //int phi = 0xb979379e;
            int phi = 0x9e3779b9;
            //(x << n) | (x >>> (32 - n)) Rotate
            int tmp;
            tmp = prekeys[i-8] ^ prekeys[i-5] ^ prekeys[i-3] ^ prekeys[i-1] ^ 
                i-8 ^ phi;
            prekeys[i] = (tmp << 11) | (tmp >>> (21));
            prnt = new byte[4];
            Packing.unpackIntBigEndian(prekeys[i], prnt, 0);
          //  System.out.println("Prekey " + i + ": " + Hex.toString(prnt));
        }
    }

    private static byte[][] LTtable = new byte[][] {
        {16,  52,  56,  70,  83,  94, 105, xFF},
        {72, 114, 125, xFF, xFF, xFF, xFF, xFF},
        { 2,   9,  15,  30,  76,  84, 126, xFF},
        {36,  90, 103, xFF, xFF, xFF, xFF, xFF},
        {20,  56,  60,  74,  87,  98, 109, xFF},
        { 1,  76, 118, xFF, xFF, xFF, xFF, xFF},
        { 2,   6,  13,  19,  34,  80,  88, xFF},
        {40,  94, 107, xFF, xFF, xFF, xFF, xFF},
        {24,  60,  64,  78,  91, 102, 113, xFF},
        { 5,  80, 122, xFF, xFF, xFF, xFF, xFF},
        { 6,  10,  17,  23,  38,  84,  92, xFF},
        {44,  98, 111, xFF, xFF, xFF, xFF, xFF},
        {28,  64,  68,  82,  95, 106, 117, xFF},
        { 9,  84, 126, xFF, xFF, xFF, xFF, xFF},
        {10,  14,  21,  27,  42,  88,  96, xFF},
        {48, 102, 115, xFF, xFF, xFF, xFF, xFF},
        {32,  68,  72,  86,  99, 110, 121, xFF},
        { 2,  13,  88, xFF, xFF, xFF, xFF, xFF},
        {14,  18,  25,  31,  46,  92, 100, xFF},
        {52, 106, 119, xFF, xFF, xFF, xFF, xFF},
        {36,  72,  76,  90, 103, 114, 125, xFF},
        { 6,  17,  92, xFF, xFF, xFF, xFF, xFF},
        {18,  22,  29,  35,  50,  96, 104, xFF},
        {56, 110, 123, xFF, xFF, xFF, xFF, xFF},
        { 1,  40,  76,  80,  94, 107, 118, xFF},
        {10,  21,  96, xFF, xFF, xFF, xFF, xFF},
        {22,  26,  33,  39,  54, 100, 108, xFF},
        {60, 114, 127, xFF, xFF, xFF, xFF, xFF},
        { 5,  44,  80,  84,  98, 111, 122, xFF},
        {14,  25, 100, xFF, xFF, xFF, xFF, xFF},
        {26,  30,  37,  43,  58, 104, 112, xFF},
        { 3, 118, xFF, xFF, xFF, xFF, xFF, xFF},
        { 9,  48,  84,  88, 102, 115, 126, xFF},
        {18,  29, 104, xFF, xFF, xFF, xFF, xFF},
        {30,  34,  41,  47,  62, 108, 116, xFF},
        { 7, 122, xFF, xFF, xFF, xFF, xFF, xFF},
        { 2,  13,  52,  88,  92, 106, 119, xFF},
        {22,  33, 108, xFF, xFF, xFF, xFF, xFF},
        {34,  38,  45,  51,  66, 112, 120, xFF},
        {11, 126, xFF, xFF, xFF, xFF, xFF, xFF},
        { 6,  17,  56,  92,  96, 110, 123, xFF},
        {26,  37, 112, xFF, xFF, xFF, xFF, xFF},
        {38,  42,  49,  55,  70, 116, 124, xFF},
        { 2,  15,  76, xFF, xFF, xFF, xFF, xFF},
        {10,  21,  60,  96, 100, 114, 127, xFF},
        {30,  41, 116, xFF, xFF, xFF, xFF, xFF},
        { 0,  42,  46,  53,  59,  74, 120, xFF},
        { 6,  19,  80, xFF, xFF, xFF, xFF, xFF},
        { 3,  14,  25, 100, 104, 118, xFF, xFF},
        {34,  45, 120, xFF, xFF, xFF, xFF, xFF},
        { 4,  46,  50,  57,  63,  78, 124, xFF},
        {10,  23,  84, xFF, xFF, xFF, xFF, xFF},
        { 7,  18,  29, 104, 108, 122, xFF, xFF},
        {38,  49, 124, xFF, xFF, xFF, xFF, xFF},
        { 0,   8,  50,  54,  61,  67,  82, xFF},
        {14,  27,  88, xFF, xFF, xFF, xFF, xFF},
        {11,  22,  33, 108, 112, 126, xFF, xFF},
        { 0,  42,  53, xFF, xFF, xFF, xFF, xFF},
        { 4,  12,  54,  58,  65,  71,  86, xFF},
        {18,  31,  92, xFF, xFF, xFF, xFF, xFF},
        { 2,  15,  26,  37,  76, 112, 116, xFF},
        { 4,  46,  57, xFF, xFF, xFF, xFF, xFF},
        { 8,  16,  58,  62,  69,  75,  90, xFF},
        {22,  35,  96, xFF, xFF, xFF, xFF, xFF},
        { 6,  19,  30,  41,  80, 116, 120, xFF},
        { 8,  50,  61, xFF, xFF, xFF, xFF, xFF},
        {12,  20,  62,  66,  73,  79,  94, xFF},
        {26,  39, 100, xFF, xFF, xFF, xFF, xFF},
        {10,  23,  34,  45,  84, 120, 124, xFF},
        {12,  54,  65, xFF, xFF, xFF, xFF, xFF},
        {16,  24,  66,  70,  77,  83,  98, xFF},
        {30,  43, 104, xFF, xFF, xFF, xFF, xFF},
        { 0,  14,  27,  38,  49,  88, 124, xFF},
        {16,  58,  69, xFF, xFF, xFF, xFF, xFF},
        {20,  28,  70,  74,  81,  87, 102, xFF},
        {34,  47, 108, xFF, xFF, xFF, xFF, xFF},
        { 0,   4,  18,  31,  42,  53,  92, xFF},
        {20,  62,  73, xFF, xFF, xFF, xFF, xFF},
        {24,  32,  74,  78,  85,  91, 106, xFF},
        {38,  51, 112, xFF, xFF, xFF, xFF, xFF},
        { 4,   8,  22,  35,  46,  57,  96, xFF},
        {24,  66,  77, xFF, xFF, xFF, xFF, xFF},
        {28,  36,  78,  82,  89,  95, 110, xFF},
        {42,  55, 116, xFF, xFF, xFF, xFF, xFF},
        { 8,  12,  26,  39,  50,  61, 100, xFF},
        {28,  70,  81, xFF, xFF, xFF, xFF, xFF},
        {32,  40,  82,  86,  93,  99, 114, xFF},
        {46,  59, 120, xFF, xFF, xFF, xFF, xFF},
        {12,  16,  30,  43,  54,  65, 104, xFF},
        {32,  74,  85, xFF, xFF, xFF, xFF, xFF},
        {36,  90, 103, 118, xFF, xFF, xFF, xFF},
        {50,  63, 124, xFF, xFF, xFF, xFF, xFF},
        {16,  20,  34,  47,  58,  69, 108, xFF},
        {36,  78,  89, xFF, xFF, xFF, xFF, xFF},
        {40,  94, 107, 122, xFF, xFF, xFF, xFF},
        { 0,  54,  67, xFF, xFF, xFF, xFF, xFF},
        {20,  24,  38,  51,  62,  73, 112, xFF},
        {40,  82,  93, xFF, xFF, xFF, xFF, xFF},
        {44,  98, 111, 126, xFF, xFF, xFF, xFF},
        { 4,  58,  71, xFF, xFF, xFF, xFF, xFF},
        {24,  28,  42,  55,  66,  77, 116, xFF},
        {44,  86,  97, xFF, xFF, xFF, xFF, xFF},
        { 2,  48, 102, 115, xFF, xFF, xFF, xFF},
        { 8,  62,  75, xFF, xFF, xFF, xFF, xFF},
        {28,  32,  46,  59,  70,  81, 120, xFF},
        {48,  90, 101, xFF, xFF, xFF, xFF, xFF},
        { 6,  52, 106, 119, xFF, xFF, xFF, xFF},
        {12,  66,  79, xFF, xFF, xFF, xFF, xFF},
        {32,  36,  50,  63,  74,  85, 124, xFF},
        {52,  94, 105, xFF, xFF, xFF, xFF, xFF},
        {10,  56, 110, 123, xFF, xFF, xFF, xFF},
        {16,  70,  83, xFF, xFF, xFF, xFF, xFF},
        { 0,  36,  40,  54,  67,  78,  89, xFF},
        {56,  98, 109, xFF, xFF, xFF, xFF, xFF},
        {14,  60, 114, 127, xFF, xFF, xFF, xFF},
        {20,  74,  87, xFF, xFF, xFF, xFF, xFF},
        { 4,  40,  44,  58,  71,  82,  93, xFF},
        {60, 102, 113, xFF, xFF, xFF, xFF, xFF},
        { 3,  18,  72, 114, 118, 125, xFF, xFF},
        {24,  78,  91, xFF, xFF, xFF, xFF, xFF},
        { 8,  44,  48,  62,  75,  86,  97, xFF},
        {64, 106, 117, xFF, xFF, xFF, xFF, xFF},
        { 1,   7,  22,  76, 118, 122, xFF, xFF},
        {28,  82,  95, xFF, xFF, xFF, xFF, xFF},
        {12,  48,  52,  66,  79,  90, 101, xFF},
        {68, 110, 121, xFF, xFF, xFF, xFF, xFF},
        { 5,  11,  26,  80, 122, 126, xFF, xFF},
        {32,  86,  99, xFF, xFF, xFF, xFF, xFF}
    };
    private static byte[] LT (byte[] data) { 
    	byte[] output = new byte[16];
    	ByteBuffer buffer = ByteBuffer.wrap(data);
    	//buffer.order(ByteOrder.LITTLE_ENDIAN);
    	int[] x = {buffer.getInt(),buffer.getInt(),buffer.getInt(),buffer.getInt()};

    	int j, b;
        int[] result = new int[4];
        for (int i = 0; i < 128; i++) {
            b = 0;
            j = 0;
            while (LTtable[i][j] != xFF) {
                b ^= (x[(LTtable[i][j] & 0x7F) / 32] >>> ((LTtable[i][j] & 0x7F) % 32)) & 0x01;
                j++;
            }
            if ((b & 0x01) == 1)
                result[i / 32] |= 1 << (i % 32); // set it
            else
                result[i / 32] &= ~(1 << (i % 32)); // clear it
        }
        
    	buffer.clear();
    	buffer.putInt(result[0]);
    	buffer.putInt(result[1]);
    	buffer.putInt(result[2]);
    	buffer.putInt(result[3]);
    	output = buffer.array();
    	return output;
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
            //System.out.println(Hex.toString(roundKey));
            for(int n = 0; n < 16; n++){
                text[n] = (byte) (text[n] ^ roundKey[n]);
            }
            System.out.println(i+"XOR: "+Hex.toString(text));
            text = sBox(text, i);
            System.out.println(i+"S: "+Hex.toString(text));
            if(i == 31){
            	roundKey = getRoundKey(32);
                for(int n = 0; n < 16; n++){
                    text[n] = (byte) (text[n] ^ roundKey[n]);
                }
                System.out.println("32XOR: "+Hex.toString(text));
            }
            else{

//           	 	byte[] blank = new byte[] {
//               	 		(byte) 0xF0,0x00,0x00,0x00,(byte) 0x00,0x00,0x00,0x00,
//                        (byte) 0x00,0x00,0x00,0x00,(byte) 0x00,0x00,0x00,(byte) 0x00,
//                     };
//
//                byte[] BhatiPlus1 = linearTransform(blank);
            	
            	text = linearTransform(text);
            	System.out.println(i+"LT: "+Hex.toString(text));
            }
        }
        
        text = finalPermutation(text);   
      byte[] temp = new byte[] {
    		  text[3], text[2], text[1], text[0],
    		  text[7], text[6], text[5], text[4],
    		  text[11], text[10], text[9], text[8],
    		  text[15], text[14], text[13], text[12],
      };
      text = temp;
        System.out.println(Hex.toString(text));
    }
    
    private byte[] initPermutation(byte[] data) {
        byte[] output = new byte[16];
        for (int i = 0;  i < 128; i++) {
            int bit = (data[(ipTable[i]) / 8] >>> ((ipTable[i]) % 8)) & 0x01;
            if ((bit & 0x01) == 1)
                output[15- (i/8)] |= 1 << (i % 8);
            else
                output[15 - (i/8)] &= ~(1 << (i % 8));
        }
        return output; 
    }

    private byte[] finalPermutation(byte[] data) {
        byte[] output = new byte[16];
        for (int i = 0;  i < 128; i++) {
            int bit = (data[15-fpTable[i] / 8] >>> (fpTable[i] % 8)) & 0x01;
            if ((bit & 0x01) == 1)
                output[(i/8)] |= 1 << (i % 8);
            else
                output[(i/8)] &= ~(1 << (i % 8));
        }
//        byte[] result = new byte[] {
//                output[3], output[2], output[1], output[0],
//                output[7], output[6], output[5], output[4],
//                output[11], output[10], output[9], output[8],
//                output[15], output[14], output[13], output[12],
//            };
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
            output[i] = (byte) ((toUse[low4]<<4) ^ (toUse[high4]));
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
    	data = finalPermutation(data);
    	byte[] output = new byte[blockSize()];
    	ByteBuffer buffer = ByteBuffer.wrap(data);
    	//buffer.order(ByteOrder.LITTLE_ENDIAN);
    	int x0 =  buffer.getInt();
    	int x1 =  buffer.getInt();
    	int x2 =  buffer.getInt();
    	int x3 =  buffer.getInt();
    	
    	System.out.print("before :"+Hex.toString(x0)+" ");
    	System.out.print(Hex.toString(x1)+" ");
    	System.out.print(Hex.toString(x2)+" ");
    	System.out.println(Hex.toString(x3)+" ");
    	x0 = ((x0 << 13) | (x0 >>> (32 - 13)));	
    	x2 = ((x2 << 3) | (x2 >>> (32 - 3)));
    	x1 = x1 ^ x0 ^ x2;
    	x3 = x3 ^ x2 ^ (x0 << 3);
    	x1 = (x1 << 1) | (x1 >>> (32 - 1));
    	x3 = (x3 << 7) | (x3 >>> (32 - 7));
    	x0 = x0 ^ x1 ^ x3;
    	x2 = x2 ^ x3 ^ (x1 << 7);
    	x0 = (x0 << 5) | (x0 >>> (32-5));
    	x2 = (x2 << 22) | (x2 >>> (32-22));

    	buffer.clear();

    	buffer.putInt(x0);
    	buffer.putInt(x1);
    	buffer.putInt(x2);
    	buffer.putInt(x3);
    	
    	output = buffer.array();
    	output = initPermutation(output);
    	
    	System.out.println("after:"+Hex.toString(output)+" ");
    	return output;
    }
    private byte[] getRoundKey(int round) {
        int k0 = prekeys[4*round+8];
        int k1 = prekeys[4*round+9];
        int k2 = prekeys[4*round+10];
        int k3 = prekeys[4*round+11];
        int box = (((3-round)%8)+8)%8;
        byte[] in = new byte[16];
        for (int j = 0; j < 32; j+=2) {
            in[j/2] = (byte) (((k0 >>> j) & 0x01)     |
            ((k1 >>> j) & 0x01) << 1 |
            ((k2 >>> j) & 0x01) << 2 |
            ((k3 >>> j) & 0x01) << 3 |
            ((k0 >>> j+1) & 0x01) << 4 |
            ((k1 >>> j+1) & 0x01) << 5 |
            ((k2 >>> j+1) & 0x01) << 6 |
            ((k3 >>> j+1) & 0x01) << 7 );
        }
        byte[] out = sBox(in, box);
        byte[] key = new byte[16];
//        for (int i = 3; i >= 0; i--) {
//            for(int j = 0; j < 4; j++) {
//                key[i] |= (out[i*4+j] & 0x01) << (j*2) | ((out[i*4+j] >>> 4) & 0x01) << (j*2+1) ;
//                key[4+i] |= ((out[i*4+j] >>> 1) & 0x01) << (j*2) | ((out[i*4+j] >>> 5) & 0x01) << (j*2+1) ;
//                key[8+i] |= ((out[i*4+j] >>> 2) & 0x01) << (j*2) | ((out[i*4+j] >>> 6) & 0x01) << (j*2+1) ;
//                key[12+i] |= ((out[i*4+j] >>> 3) & 0x01) << (j*2) | ((out[i*4+j] >>> 7) & 0x01) << (j*2+1) ;
//            }
//        }
        for (int i = 3; i >= 0; i--) {
            for(int j = 0; j < 4; j++) {
                key[3-i] |= (out[i*4+j] & 0x01) << (j*2) | ((out[i*4+j] >>> 4) & 0x01) << (j*2+1) ;
                key[7-i] |= ((out[i*4+j] >>> 1) & 0x01) << (j*2) | ((out[i*4+j] >>> 5) & 0x01) << (j*2+1) ;
                key[11-i] |= ((out[i*4+j] >>> 2) & 0x01) << (j*2) | ((out[i*4+j] >>> 6) & 0x01) << (j*2+1) ;
                key[15-i] |= ((out[i*4+j] >>> 3) & 0x01) << (j*2) | ((out[i*4+j] >>> 7) & 0x01) << (j*2+1) ;
            }
        }
        return initPermutation(key);
    }

    /**
     * Main function, does one of two things:
     * sets an all-zero-byte key, performs N encryptions of an all-zero-byte plaintext block
     * or 
     * encrypts the contents of the input file, storing the result in an output file
     * args either specifies N or input file, output file, key, and nonce
     */
    public static void main( String[] args ) {
        Serpent serpent = new Serpent();
        if(args.length == 1)
        {
       	 	byte[] test_in = new byte[] {
       	 		0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
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
           // System.out.println(Hex.toString(test_in));
            
        }
        else if (args.length == 4) {
            //read file
        	try{
            File file_in = new File(args[0]);
            byte [] fileData = new byte[(int)file_in.length()];
            DataInputStream in_stream = new DataInputStream((new FileInputStream(file_in)));
            in_stream.readFully(fileData);
            in_stream.close();
            //add nonce to key
            byte[] key = Hex.toByteArray(args[2]);
            //set key
            serpent.setKey(key);
            //setup file writing
            File file_out = new File(args[1]);
            DataOutputStream out_stream = new DataOutputStream((new FileOutputStream(file_out)));
            //encrypt
            byte[] iv = serpent.getRoundKey(Integer.parseInt(args[3]));
            for(int i = 0; i < fileData.length; i+=16){
                byte[] block = new byte[] {
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                    0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                };
                for(int n = 0; n < 16 && n < fileData.length; n++){
                    block[n] = (byte) (fileData[i+n] ^ iv[n]);
                }
                serpent.encrypt(block);
                iv = block;
                out_stream.write(block, 0, block.length);
            }
            out_stream.close();
        	}
        	catch(IOException e){
        		System.err.println(e.getMessage());
        	}
        }
        //sBoxTest();
        //setKeyTest();
        //IPTest();
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

    private static void IPTest() {
        Serpent tSerp = new Serpent();
        byte[] test = new byte[]{
            0x00,0x01,0x02,0x03,
            0x04,0x05,0x06,0x07,
            0x08,0x09,0x0a,0x0b,
            0x0c,0x0d,0x0e,0x0f
        };
        System.out.println("IP Test1: "+Hex.toString(test));
        System.out.println("Out Test1: "+Hex.toString(tSerp.initPermutation(test)));
    }
}//Serpent.java


