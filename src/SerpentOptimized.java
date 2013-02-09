import edu.rit.util.Hex;
import edu.rit.util.Packing;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.Arrays;
import java.lang.Integer;
import java.io.*;

public class SerpentOptimized implements BlockCipher {

    private static final byte xFF = (byte)0xFF;
	private int keySize;
    private byte[] key;
    private int[] prekeys;

    public SerpentOptimized() {
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
        }
        //Build out prekey array
        for( int i = 8; i < prekeys.length; i++ ) {
            byte[] prnt = new byte[4];
            int phi = 0x9e3779b9;
            //(x << n) | (x >>> (32 - n)) Rotate
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
		//System.out.println(Hex.toString(data));
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
           // System.out.println("key:"+Hex.toString(roundKey));
            for(int n = 0; n < 16; n++){
                data[n] = (byte) (data[n] ^ roundKey[n]);
            }
          //  System.out.println(Hex.toString(data));
            data = sBox(data, i);
          //  System.out.println(Hex.toString(data));
            
            if(i == 31){
            	roundKey = getRoundKey(32);
                for(int n = 0; n < 16; n++){
                    data[n] = (byte) (data[n] ^ roundKey[n]);
                } 
            }
            else{
            	data = linearTransform(data);
          //  	System.out.println(Hex.toString(data));
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

    /**
     * Perform initial permutation on the input
     *
     * @param data Input bit sequence
     */
    private byte[] initPermutation(byte[] input) {
        byte[] output = new byte[16];
        output[15] = (byte) ((((input[0] & 0x01))) | (((input[4])& 0x01) << 1) | (((input[8])& 0x01) << 2) | (((input[12])& 0x01) << 3) | 
                     (((input[0]>>>1)& 0x01) << 4) | (((input[4]>>>1)& 0x01) << 5) | (((input[8]>>>1)& 0x01) << 6) | (((input[12]>>>1)& 0x01) << 7));
        output[14] = (byte) ((((input[0]>>>2 & 0x01))) | (((input[4]>>>2)& 0x01) << 1) | (((input[8]>>>2)& 0x01) << 2) | (((input[12]>>>2)& 0x01) << 3) | 
                     (((input[0]>>>3)& 0x01) << 4) | (((input[4]>>>3)& 0x01) << 5) | (((input[8]>>>3)& 0x01) << 6) | (((input[12]>>>3)& 0x01) << 7));
        output[13] = (byte) ((((input[0]>>>4 & 0x01))) | (((input[4]>>>4)& 0x01) << 1) | (((input[8]>>>4)& 0x01) << 2) | (((input[12]>>>4)& 0x01) << 3) | 
                     (((input[0]>>>5)& 0x01) << 4) | (((input[4]>>>5)& 0x01) << 5) | (((input[8]>>>5)& 0x01) << 6) | (((input[12]>>>5)& 0x01) << 7));
        output[12] = (byte) ((((input[0]>>>6 & 0x01))) | (((input[4]>>>6)& 0x01) << 1) | (((input[8]>>>6)& 0x01) << 2) | (((input[12]>>>6)& 0x01) << 3) | 
                    (((input[0]>>>7)& 0x01) << 4) | (((input[4]>>>7)& 0x01) << 5) | (((input[8]>>>7)& 0x01) << 6) | (((input[12]>>>7)& 0x01) << 7));
        
        output[11] = (byte) ((((input[1] & 0x01))) | (((input[5])& 0x01) << 1) | (((input[9])& 0x01) << 2) | (((input[13])& 0x01) << 3) | 
                    (((input[1]>>>1)& 0x01) << 4) | (((input[5]>>>1)& 0x01) << 5) | (((input[9]>>>1)& 0x01) << 6) | (((input[13]>>>1)& 0x01) << 7));
        output[10] = (byte) ((((input[1]>>>2 & 0x01))) | (((input[5]>>>2)& 0x01) << 1) | (((input[9]>>>2)& 0x01) << 2) | (((input[13]>>>2)& 0x01) << 3) | 
                    (((input[1]>>>3)& 0x01) << 4) | (((input[5]>>>3)& 0x01) << 5) | (((input[9]>>>3)& 0x01) << 6) | (((input[13]>>>3)& 0x01) << 7));
        output[9] = (byte) ((((input[1]>>>4 & 0x01))) | (((input[5]>>>4)& 0x01) << 1) | (((input[9]>>>4)& 0x01) << 2) | (((input[13]>>>4)& 0x01) << 3) | 
                    (((input[1]>>>5)& 0x01) << 4) | (((input[5]>>>5)& 0x01) << 5) | (((input[9]>>>5)& 0x01) << 6) | (((input[13]>>>5)& 0x01) << 7));
        output[8] = (byte) ((((input[1]>>>6 & 0x01))) | (((input[5]>>>6)& 0x01) << 1) | (((input[9]>>>6)& 0x01) << 2) | (((input[13]>>>6)& 0x01) << 3) | 
                    (((input[1]>>>7)& 0x01) << 4) | (((input[5]>>>7)& 0x01) << 5) | (((input[9]>>>7)& 0x01) << 6) | (((input[13]>>>7)& 0x01) << 7));
        
        output[7] = (byte) ((((input[2] & 0x01))) | (((input[6])& 0x01) << 1) | (((input[10])& 0x01) << 2) | (((input[14])& 0x01) << 3) | 
                    (((input[2]>>>1)& 0x01) << 4) | (((input[6]>>>1)& 0x01) << 5) | (((input[10]>>>1)& 0x01) << 6) | (((input[14]>>>1)& 0x01) << 7));
        output[6] = (byte) ((((input[2]>>>2 & 0x01))) | (((input[6]>>>2)& 0x01) << 1) | (((input[10]>>>2)& 0x01) << 2) | (((input[14]>>>2)& 0x01) << 3) | 
                    (((input[2]>>>3)& 0x01) << 4) | (((input[6]>>>3)& 0x01) << 5) | (((input[10]>>>3)& 0x01) << 6) | (((input[14]>>>3)& 0x01) << 7));
        output[5] = (byte) ((((input[2]>>>4 & 0x01))) | (((input[6]>>>4)& 0x01) << 1) | (((input[10]>>>4)& 0x01) << 2) | (((input[14]>>>4)& 0x01) << 3) | 
                    (((input[2]>>>5)& 0x01) << 4) | (((input[6]>>>5)& 0x01) << 5) | (((input[10]>>>5)& 0x01) << 6) | (((input[14]>>>5)& 0x01) << 7));
        output[4] = (byte) ((((input[2]>>>6 & 0x01))) | (((input[6]>>>6)& 0x01) << 1) | (((input[10]>>>6)& 0x01) << 2) | (((input[14]>>>6)& 0x01) << 3) | 
                    (((input[2]>>>7)& 0x01) << 4) | (((input[6]>>>7)& 0x01) << 5) | (((input[10]>>>7)& 0x01) << 6) | (((input[14]>>>7)& 0x01) << 7));

        output[3] = (byte) ((((input[3] & 0x01))) | (((input[7])& 0x01) << 1) | (((input[11])& 0x01) << 2) | (((input[15])& 0x01) << 3) | 
                    (((input[3]>>>1)& 0x01) << 4) | (((input[7]>>>1)& 0x01) << 5) | (((input[11]>>>1)& 0x01) << 6) | (((input[15]>>>1)& 0x01) << 7));
        output[2] = (byte) ((((input[3]>>>2 & 0x01))) | (((input[7]>>>2)& 0x01) << 1) | (((input[11]>>>2)& 0x01) << 2) | (((input[15]>>>2)& 0x01) << 3) | 
                    (((input[3]>>>3)& 0x01) << 4) | (((input[7]>>>3)& 0x01) << 5) | (((input[11]>>>3)& 0x01) << 6) | (((input[15]>>>3)& 0x01) << 7));
        output[1] = (byte) ((((input[3]>>>4 & 0x01))) | (((input[7]>>>4)& 0x01) << 1) | (((input[11]>>>4)& 0x01) << 2) | (((input[15]>>>4)& 0x01) << 3) | 
                    (((input[3]>>>5)& 0x01) << 4) | (((input[7]>>>5)& 0x01) << 5) | (((input[11]>>>5)& 0x01) << 6) | (((input[15]>>>5)& 0x01) << 7));
        output[0] = (byte) ((((input[3]>>>6 & 0x01))) | (((input[7]>>>6)& 0x01) << 1) | (((input[11]>>>6)& 0x01) << 2) | (((input[15]>>>6)& 0x01) << 3) | 
                    (((input[3]>>>7)& 0x01) << 4) | (((input[7]>>>7)& 0x01) << 5) | (((input[11]>>>7)& 0x01) << 6) | (((input[15]>>>7)& 0x01) << 7));
                    
        return output; 
    }

    /**
     * Perform finalls
      permutation on the input
     *
     * @param data Input bit sequence
     */
    private byte[] finalPermutation(byte[] input) {
        byte[] output = new byte[16];
        output[0] = (byte) ((((input[15]>>>0) & 0x01)) | (((input[15]>>>4)& 0x01) << 1) | (((input[14]>>>0)& 0x01) << 2) | (((input[14]>>>4)& 0x01) << 3) | 
                     (((input[13]>>>0)& 0x01) << 4) | (((input[13]>>>4)& 0x01) << 5) | (((input[12]>>>0)& 0x01) << 6) | (((input[12]>>>4)& 0x01) << 7));
        output[1] = (byte) ((((input[11]>>>0) & 0x01)) | (((input[11]>>>4)& 0x01) << 1) | (((input[10]>>>0)& 0x01) << 2) | (((input[10]>>>4)& 0x01) << 3) | 
                     (((input[9]>>>0)& 0x01) << 4) | (((input[9]>>>4)& 0x01) << 5) | (((input[8]>>>0)& 0x01) << 6) | (((input[8]>>>4)& 0x01) << 7));
        output[2] = (byte) ((((input[7]>>>0) & 0x01)) | (((input[7]>>>4)& 0x01) << 1) | (((input[6]>>>0)& 0x01) << 2) | (((input[6]>>>4)& 0x01) << 3) | 
                     (((input[5]>>>0)& 0x01) << 4) | (((input[5]>>>4)& 0x01) << 5) | (((input[4]>>>0)& 0x01) << 6) | (((input[4]>>>4)& 0x01) << 7));
        output[3] = (byte) ((((input[3]>>>0) & 0x01)) | (((input[3]>>>4)& 0x01) << 1) | (((input[2]>>>0)& 0x01) << 2) | (((input[2]>>>4)& 0x01) << 3) | 
                    (((input[1]>>>0)& 0x01) << 4) | (((input[1]>>>4)& 0x01) << 5) | (((input[0]>>>0)& 0x01) << 6) | (((input[0]>>>4)& 0x01) << 7));
        
        output[4] = (byte) ((((input[15]>>>1) & 0x01)) | (((input[15]>>>5)& 0x01) << 1) | (((input[14]>>>1)& 0x01) << 2) | (((input[14]>>>5)& 0x01) << 3) | 
                     (((input[13]>>>1)& 0x01) << 4) | (((input[13]>>>5)& 0x01) << 5) | (((input[12]>>>1)& 0x01) << 6) | (((input[12]>>>5)& 0x01) << 7));
        output[5] = (byte) ((((input[11]>>>1) & 0x01)) | (((input[11]>>>5)& 0x01) << 1) | (((input[10]>>>1)& 0x01) << 2) | (((input[10]>>>5)& 0x01) << 3) | 
                     (((input[9]>>>1)& 0x01) << 4) | (((input[9]>>>5)& 0x01) << 5) | (((input[8]>>>1)& 0x01) << 6) | (((input[8]>>>5)& 0x01) << 7));
        output[6] = (byte) ((((input[7]>>>1) & 0x01)) | (((input[7]>>>5)& 0x01) << 1) | (((input[6]>>>1)& 0x01) << 2) | (((input[6]>>>5)& 0x01) << 3) | 
                     (((input[5]>>>1)& 0x01) << 4) | (((input[5]>>>5)& 0x01) << 5) | (((input[4]>>>1)& 0x01) << 6) | (((input[4]>>>5)& 0x01) << 7));
        output[7] = (byte) ((((input[3]>>>1) & 0x01)) | (((input[3]>>>5)& 0x01) << 1) | (((input[2]>>>1)& 0x01) << 2) | (((input[2]>>>5)& 0x01) << 3) | 
                    (((input[1]>>>1)& 0x01) << 4) | (((input[1]>>>5)& 0x01) << 5) | (((input[0]>>>1)& 0x01) << 6) | (((input[0]>>>5)& 0x01) << 7));

        output[8] = (byte) ((((input[15]>>>2) & 0x01)) | (((input[15]>>>6)& 0x01) << 1) | (((input[14]>>>2)& 0x01) << 2) | (((input[14]>>>6)& 0x01) << 3) | 
                     (((input[13]>>>2)& 0x01) << 4) | (((input[13]>>>6)& 0x01) << 5) | (((input[12]>>>2)& 0x01) << 6) | (((input[12]>>>6)& 0x01) << 7));
        output[9] = (byte) ((((input[11]>>>2) & 0x01)) | (((input[11]>>>6)& 0x01) << 1) | (((input[10]>>>2)& 0x01) << 2) | (((input[10]>>>6)& 0x01) << 3) | 
                     (((input[9]>>>2)& 0x01) << 4) | (((input[9]>>>6)& 0x01) << 5) | (((input[8]>>>2)& 0x01) << 6) | (((input[8]>>>6)& 0x01) << 7));
        output[10] = (byte) ((((input[7]>>>2) & 0x01)) | (((input[7]>>>6)& 0x01) << 1) | (((input[6]>>>2)& 0x01) << 2) | (((input[6]>>>6)& 0x01) << 3) | 
                     (((input[5]>>>2)& 0x01) << 4) | (((input[5]>>>6)& 0x01) << 5) | (((input[4]>>>2)& 0x01) << 6) | (((input[4]>>>6)& 0x01) << 7));
        output[11] = (byte) ((((input[3]>>>2) & 0x01)) | (((input[3]>>>6)& 0x01) << 1) | (((input[2]>>>2)& 0x01) << 2) | (((input[2]>>>6)& 0x01) << 3) | 
                    (((input[1]>>>2)& 0x01) << 4) | (((input[1]>>>6)& 0x01) << 5) | (((input[0]>>>2)& 0x01) << 6) | (((input[0]>>>6)& 0x01) << 7));

        output[12] = (byte) ((((input[15]>>>3) & 0x01)) | (((input[15]>>>7)& 0x01) << 1) | (((input[14]>>>3)& 0x01) << 2) | (((input[14]>>>7)& 0x01) << 3) | 
                     (((input[13]>>>3)& 0x01) << 4) | (((input[13]>>>7)& 0x01) << 5) | (((input[12]>>>3)& 0x01) << 6) | (((input[12]>>>7)& 0x01) << 7));
        output[13] = (byte) ((((input[11]>>>3) & 0x01)) | (((input[11]>>>7)& 0x01) << 1) | (((input[10]>>>3)& 0x01) << 2) | (((input[10]>>>7)& 0x01) << 3) | 
                     (((input[9]>>>3)& 0x01) << 4) | (((input[9]>>>7)& 0x01) << 5) | (((input[8]>>>3)& 0x01) << 6) | (((input[8]>>>7)& 0x01) << 7));
        output[14] = (byte) ((((input[7]>>>3) & 0x01)) | (((input[7]>>>7)& 0x01) << 1) | (((input[6]>>>3)& 0x01) << 2) | (((input[6]>>>7)& 0x01) << 3) | 
                     (((input[5]>>>3)& 0x01) << 4) | (((input[5]>>>7)& 0x01) << 5) | (((input[4]>>>3)& 0x01) << 6) | (((input[4]>>>7)& 0x01) << 7));
        output[15] = (byte) ((((input[3]>>>3) & 0x01)) | (((input[3]>>>7)& 0x01) << 1) | (((input[2]>>>3)& 0x01) << 2) | (((input[2]>>>7)& 0x01) << 3) | 
                    (((input[1]>>>3)& 0x01) << 4) | (((input[1]>>>7)& 0x01) << 5) | (((input[0]>>>3)& 0x01) << 6) | (((input[0]>>>7)& 0x01) << 7));

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
    
    /**
     * Performs linear transformation on the input bit sequence
     * 
     * @param data Input bit sequence
     * @return output bit sequence
     */
    private byte[] linearTransform(byte[] data){
    	data = finalPermutation(data);
    	//byte[] output = new byte[blockSize()];
    	ByteBuffer buffer = ByteBuffer.wrap(data);
    	//buffer.order(ByteOrder.LITTLE_ENDIAN);
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
    	
    	data = buffer.array();
    	data = initPermutation(data);
    	
    	return data;
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

        data = buffer.array();
        data = initPermutation(data);

        return data;
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
        SerpentOptimized serpent = new SerpentOptimized();
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
}//Serpent.java


