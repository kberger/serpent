public interface BlockCipher
	{

	/**
	 * Returns this block cipher's block size in bytes.
	 *
	 * @return  Block size.
	 */
	public int blockSize();

	/**
	 * Returns this block cipher's key size in bytes.
	 *
	 * @return  Key size.
	 */
	public int keySize();

	/**
	 * Set the key for this block cipher. <TT>key</TT> must be an array of bytes
	 * whose length is equal to <TT>keySize()</TT>.
	 *
	 * @param  key  Key.
	 */
	public void setKey
		(byte[] key);

	/**
	 * Encrypt the given plaintext. <TT>text</TT> must be an array of bytes
	 * whose length is equal to <TT>blockSize()</TT>. On input, <TT>text</TT>
	 * contains the plaintext block. The plaintext block is encrypted using the
	 * key specified in the most recent call to <TT>setKey()</TT>. On output,
	 * <TT>text</TT> contains the ciphertext block.
	 *
	 * @param  text  Plaintext (on input), ciphertext (on output).
	 */
	public void encrypt
		(byte[] text);

	}
