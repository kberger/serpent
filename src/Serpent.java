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
			//Pad key to 256-bit
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
        }
        //Build out prekey array
		//There's a shift of 8 positions here because I build the intermediate keys in the same
		//array as the other prekeys.
        for( int i = 8; i < prekeys.length; i++ ) {
            byte[] prnt = new byte[4];
			//Phi is the fractional part of the golden ratio
            int phi = 0x9e3779b9;
            int tmp;
            tmp = prekeys[i-8] ^ prekeys[i-5] ^ prekeys[i-3] ^ prekeys[i-1] ^ 
                i-8 ^ phi;
            prekeys[i] = (tmp << 11) | (tmp >>> (21));
            prnt = new byte[4];
            Packing.unpackIntBigEndian(prekeys[i], prnt, 0);
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
        byte[] data = initPermutation(text);
        byte[] temp = new byte[] {
                data[12], data[13], data[14], data[15],
                data[8], data[9], data[10], data[11],
                data[4], data[5], data[6], data[7],
                data[0], data[1], data[2], data[3],
                };
        data = temp;
        byte[] roundKey = new byte[16];
        //32 rounds
        for(int i = 0; i < 32; i++){
            roundKey = getRoundKey(i);
            for(int n = 0; n < 16; n++){
                data[n] = (byte) (data[n] ^ roundKey[n]);
            }
            data = sBox(data, i);
            
            if(i == 31){
				//For round 32, instead of a linear transform
				// we get the last produced round key and xor 
				// it with the current state.
                roundKey = getRoundKey(32);
                for(int n = 0; n < 16; n++){
                    data[n] = (byte) (data[n] ^ roundKey[n]);
                } 
            }
            else{
                data = linearTransform(data);
            }
        }
        data = finalPermutation(data);   
        text[0] = data[3];
        text[1] = data[2];
        text[2] = data[1];
        text[3] = data[0];
        text[4] = data[7];
        text[5] = data[6];
        text[6] = data[5];
        text[7] = data[4];
        text[8] = data[11];
        text[9] = data[10];
        text[10] = data[9];
        text[11] = data[8];
        text[12] = data[15];
        text[13] = data[14];
        text[14] = data[13];
        text[15] = data[12];
    }

    /**
     * Decrypt the given ciphertext.  We decrypt by performing the inverse
	 * operations performed to encrypt in reverse order.
     *
     * @param  text  ciphertext (on input), original plaintext (on output).
     */
    public void decrypt(byte[] text) {
        byte[] temp = new byte[] {
                text[3], text[2], text[1], text[0],
                text[7], text[6], text[5], text[4],
                text[11], text[10], text[9], text[8],
                text[15], text[14], text[13], text[12],
            };
        byte[] data = initPermutation(temp);
        byte[] roundKey = getRoundKey(32);
        for(int n = 0; n < 16; n++){
            data[n] = (byte) (data[n] ^ roundKey[n]);
        }
        //32 rounds in reverse
        for(int i = 31; i >= 0; i--){
            if(i!=31){
                data = invLinearTransform(data);
            }
            data = sBoxInv(data, i);
            roundKey = getRoundKey(i);
            for(int n = 0; n < 16; n++){
                data[n] = (byte) (data[n] ^ roundKey[n]);
            }
        }
        data = finalPermutation(data);   
        text[0] = data[3];
        text[1] = data[2];
        text[2] = data[1];
        text[3] = data[0];
        text[4] = data[7];
        text[5] = data[6];
        text[6] = data[5];
        text[7] = data[4];
        text[8] = data[11];
        text[9] = data[10];
        text[10] = data[9];
        text[11] = data[8];
        text[12] = data[15];
        text[13] = data[14];
        text[14] = data[13];
        text[15] = data[12];
    }

    private byte[] initPermutation(byte[] data) {
        byte[] output = new byte[16];
        for (int i = 0;  i < 128; i++) {
			//Bit permutation based on ip lookup table
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
			//Bit permutation based on fp lookup table
            int bit = (data[15-fpTable[i] / 8] >>> (fpTable[i] % 8)) & 0x01;
            if ((bit & 0x01) == 1)
                output[(i/8)] |= 1 << (i % 8);
            else
                output[(i/8)] &= ~(1 << (i % 8));
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

    private static byte[] is0 = new byte[]
        {13,3,11,0,10,6,5,12,1,14,4,7,15,9,8,2};
    private static byte[] is1 = new byte[]
        {5,8,2,14,15,6,12,3,11,4,7,9,1,13,10,0};
    private static byte[] is2 = new byte[]
        {12,9,15,4,11,14,1,2,0,3,6,13,5,8,10,7};
    private static byte[] is3 = new byte[]
        {0,9,10,7,11,14,6,13,3,5,12,2,4,8,15,1};
    private static byte[] is4 = new byte[]
        {5,0,8,3,10,9,7,14,2,12,11,6,4,15,13,1};
    private static byte[] is5 = new byte[]
        {8,15,2,9,4,1,13,14,11,6,5,3,7,12,10,0};
    private static byte[] is6 = new byte[]
        {15,10,1,13,5,3,6,0,4,9,14,7,2,12,8,11};
    private static byte[] is7 = new byte[]
        {3,0,6,13,9,14,15,8,5,12,11,7,10,1,4,2};
    private static byte[][] isBoxes = new byte[][]
        {is0,is1,is2,is3,is4,is5,is6,is7};    

    /**
     * Perform inverse S-Box manipulation to the given byte array of <TT>blocksize()</TT> length.
     *
     * @param data Input bit sequence
     * @param round Number of the current round, used to determine which inverted S-Box to use.
     */
    private byte[] sBoxInv(byte[] data, int round) {
        byte[] toUse = isBoxes[round%8];
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
     * Performs linear transformation on the input bit sequence
     * 
     * @param data Input bit sequence
     * @return output bit sequence
     */
    private byte[] linearTransform(byte[] data){
        data = finalPermutation(data);
        byte[] output = new byte[blockSize()];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int x0 =  buffer.getInt();
        int x1 =  buffer.getInt();
        int x2 =  buffer.getInt();
        int x3 =  buffer.getInt();
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
        
        return output;
    }

    /**
     * Performs inverse linear transformation on the input bit sequence.
	 * This is the linear transform in reverse with inverted operations.
     * 
     * @param data Input bit sequence
     * @return output bit sequence
     */
    private byte[] invLinearTransform(byte[] data){
        data = finalPermutation(data);
        byte[] output = new byte[blockSize()];
        ByteBuffer buffer = ByteBuffer.wrap(data);
        int x0 =  buffer.getInt();
        int x1 =  buffer.getInt();
        int x2 =  buffer.getInt();
        int x3 =  buffer.getInt();

        x2 = (x2 >>> 22) | (x2 << (32-22));
        x0 = (x0 >>> 5) | (x0 << (32-5));
        x2 = x2 ^ x3 ^ (x1 << 7);
        x0 = x0 ^ x1 ^ x3;
        x3 = (x3 >>> 7) | (x3 << (32-7));
        x1 = (x1 >>> 1) | (x1 << (32-1));
        x3 = x3 ^ x2 ^ (x0 << 3);
        x1 = x1 ^ x0 ^ x2;
        x2 = (x2 >>> 3) | (x2 << (32-3));
        x0 = (x0 >>> 13) | (x0 << (32-13));
        
        buffer.clear();
        buffer.putInt(x0);
        buffer.putInt(x1);
        buffer.putInt(x2);
        buffer.putInt(x3);

        output = buffer.array();
        output = initPermutation(output);

        return output;
    }

	/**
	 * Fetches round key.  Round keys are built on request from the
	 * prekeys that were created when the key was set.
	 *
	 * @param round Number of the round for which a key is needed.
	 * @return byte[] The round key for the requested round.
	 */
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
     * args either specifies N or 
	 * input filename, output filename, key (up to 32 bytes in hex), nonce (integer), and [e]ncrypt or [d]ecrypt
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
            System.out.println(Hex.toString(test_in));
            
        }
        else if (args.length == 5) {
            //read file
            try{
            File file_in = new File(args[0]);
            byte [] fileData = new byte[(int)file_in.length()];
            DataInputStream in_stream = new DataInputStream((new FileInputStream(file_in)));
            in_stream.readFully(fileData);
            in_stream.close();
            byte[] key = Hex.toByteArray(args[2]);
            //set key
            serpent.setKey(key);
            //setup file writing
            File file_out = new File(args[1]);
            DataOutputStream out_stream = new DataOutputStream((new FileOutputStream(file_out)));
            byte[] iv = new byte[16];
			//Create Nonce from 4th argument.
            Packing.unpackIntLittleEndian(Integer.parseInt(args[3]),iv,0);
            serpent.encrypt(iv);
            //File encryption in CBC mode
            if(args[4].equals("e")) {
                for(int i = 0; i < fileData.length; i+=16){
                    byte[] block = new byte[] {
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                    };
                    for(int n = 0; n < 16 && i+n < fileData.length; n++){
                        block[n] = (byte) (fileData[i+n] ^ iv[n]);
                    }
                    serpent.encrypt(block);
                    iv = block;
                    out_stream.write(block, 0, block.length);
                }
            }
			//File decryption in CBC mode
            else if(args[4].equals("d")) {
                for(int i = 0; i < fileData.length; i+=16){
                    byte[] block = new byte[] {
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00,
                        0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00
                    };
                    for(int n = 0; n < 16 && n < fileData.length; n++){
                        block[n] = (byte) (fileData[i+n]);
                    }
                    byte[] savedForIV = Arrays.copyOf(block,16);
                    serpent.decrypt(block);
                    for(int n = 0; n < 16; n++){
                        block[n] = (byte) (block[n] ^ iv[n]);
                    }
                    iv = savedForIV;
                    out_stream.write(block, 0, block.length);
                }
            }
            else {
                System.out.println("Encrypt/Decrypt option invalid, input e or d as 5th argument.");
            }
            out_stream.close();
            }
            catch(IOException e){
              System.err.println(e.getMessage());
            }
        }
    }
	
	// Test functions below.

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

        System.out.println( Hex.toString(test0));
        byte [] test0out = serpent.sBox(test0,0);
        System.out.println( Hex.toString(test0out));
        System.out.println( Hex.toString(serpent.sBoxInv(test0out,0)));
        System.out.println();

        System.out.println( Hex.toString(test1) );
        byte [] test1out = serpent.sBox(test1,1);
        System.out.println( Hex.toString(test1out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test1out,1)));
        System.out.println();

        System.out.println( Hex.toString(test2) );
        byte [] test2out = serpent.sBox(test2,2);
        System.out.println( Hex.toString(test2out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test2out,2)));
        System.out.println();

        System.out.println( Hex.toString(test3) );
        byte [] test3out = serpent.sBox(test3,3);
        System.out.println( Hex.toString(test3out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test3out,3)));
        System.out.println();

        System.out.println( Hex.toString(test0));
        byte [] test4out = serpent.sBox(test0,4);
        System.out.println( Hex.toString(test4out));
        System.out.println( Hex.toString(serpent.sBoxInv(test4out,4)));
        System.out.println();

        System.out.println( Hex.toString(test1) );
        byte [] test5out = serpent.sBox(test1,5);
        System.out.println( Hex.toString(test5out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test5out,5)));
        System.out.println();

        System.out.println( Hex.toString(test2) );
        byte [] test6out = serpent.sBox(test2,6);
        System.out.println( Hex.toString(test6out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test6out,6)));
        System.out.println();

        System.out.println( Hex.toString(test3) );
        byte [] test7out = serpent.sBox(test3,7);
        System.out.println( Hex.toString(test7out) );
        System.out.println( Hex.toString(serpent.sBoxInv(test7out,7)));
    }

    private static void IPTest() {
        Serpent tSerp = new Serpent();
        byte[] test = new byte[]{
            (byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,
            (byte)0x9a,(byte)0xbc,(byte)0xde,(byte)0xff,
            (byte)0x12,(byte)0x34,(byte)0x56,(byte)0x78,
            (byte)0x9a,(byte)0xbc,(byte)0xde,(byte)0xff
        };
        System.out.println("Test1: "+Hex.toString(test));
        System.out.println("Init Test1: "+Hex.toString(tSerp.initPermutation(test)));
        System.out.println("InvInit Test1: "+Hex.toString(tSerp.finalPermutation(tSerp.initPermutation(test))));
        System.out.println();

        System.out.println("Final Test1: "+Hex.toString(tSerp.finalPermutation(test)));
        System.out.println("InvFinal Test1: "+Hex.toString(tSerp.initPermutation(tSerp.finalPermutation(test))));
    }

    private static void transformTest() {
        Serpent serpent = new Serpent();
        byte[] test0 = new byte[] {0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};
        byte[] test1 = new byte[] {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77,
            (byte)0x88,(byte)0x99,(byte)0xAA,(byte)0xBB,(byte)0xCC,(byte)0xDD,(byte)0xEE,(byte)0xFF};
        byte[] test2 = new byte[] {0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01,0x01};
        byte[] test3 = new byte[] {0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10,0x10};        

        System.out.println( Hex.toString(test0) );
        byte[] test0out = serpent.linearTransform(test0);
        System.out.println( Hex.toString(test0out) );
        System.out.println( Hex.toString(serpent.invLinearTransform(test0out)) );
        System.out.println();

        System.out.println( Hex.toString(test1) );
        byte[] test1out = serpent.linearTransform(test1);
        System.out.println( Hex.toString(test1out) );
        System.out.println( Hex.toString(serpent.invLinearTransform(test1out)) );
        System.out.println();

        System.out.println( Hex.toString(test2) );
        byte[] test2out = serpent.linearTransform(test2);
        System.out.println( Hex.toString(test2out) );
        System.out.println( Hex.toString(serpent.invLinearTransform(test2out)) );
        System.out.println();

        System.out.println( Hex.toString(test3) );
        byte[] test3out = serpent.linearTransform(test3);
        System.out.println( Hex.toString(test3out) );
        System.out.println( Hex.toString(serpent.invLinearTransform(test3out)) );
        System.out.println();
    }
}//Serpent.java


