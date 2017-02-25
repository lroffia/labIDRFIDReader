package labid.iso14443.mifare;

import java.util.Random;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.IvParameterSpec;

import labid.comm.ByteUtils;
import labid.comm.CableStream;
import labid.reader.RFReaderException;

/**
 * This class provides fast and easy methods for execution of Mifare commands.
 */
public class MifareReader extends labid.iso14443.ISO14443Reader
{

	private static byte MF_MACRO = 0x04;
	private static byte MF_UL_SIZE = 64;
	private static byte MF_UL_BLOCK_SIZE = 4;
	private static byte MF_BLOCK_SIZE = 16;
	private byte[] lastDetectedUid = null;

	public MifareReader()
	{
		super();
	}

	public MifareReader(CableStream s)
	{
		super(s);
	}

	public byte[] getLastUid()
	{
		return lastDetectedUid;
	}

	/**
	 * Activates a Mifare Ultralight tag and reads its memory.
	 *
	 * @param offset The first byte to be read.
	 * @param len Number of bytes to be read.
	 * @return Data read from the tag.
	 * @throws labid.iso14443.mifare.MifareException If parameters exceed memory size.
	 * @throws labid.reader.RFReaderException If unable to read a tag.
	 */
	public byte[] ReadUltralight(int offset, int len) throws RFReaderException
	{
		if (len + offset > MF_UL_SIZE)
		{
			throw new MifareException("Mifare Ultralight memory exceeded");
		}

		byte[] cmd = new byte[2];

		cmd[0] = MF_MACRO;
		cmd[1] = 0x22; //command code

		sendReceive(cmd, "Unable to read");

		byte[] result = new byte[len];

		ByteUtils.copy(recv_buf, 5 + offset, result, 0, len);
		return result;
	}

	/**
	 * Activates a Mifare Ultralight or UltralightC tag and reads its memory.
	 * @param firstBlock 0 based index of the first block to be read.
	 * @param nBlocks Number of block to be read.
	 * @param skipActivation Skips the activation sequence before reading the tag.
	 * @param rfReset Run an RfReset before reading the tag.
	 * @return Data read from the tag
	 * @throws RFReaderException
	 */
	public byte[] ReadUltralightC(int firstBlock, int nBlocks, boolean skipActivation, boolean rfReset)
			throws RFReaderException
	{
		byte[] cmd = new byte[5];

		cmd[0] = MF_MACRO;
		cmd[1] = 0x24; //command code
		cmd[2] = ByteUtils.composeByte(skipActivation, rfReset, false, false, false, false, false, false);
		cmd[3] = (byte) firstBlock;
		cmd[4] = (byte) nBlocks;

		sendReceive(cmd, "Unable to read");

		byte[] result = new byte[MF_UL_BLOCK_SIZE * nBlocks];

		ByteUtils.copy(recv_buf, 5, result, 0, result.length);
		return result;
	}

	/**
	 * Activates a Mifare Ultralight tag and reads its full memory
	 *
	 * @return Data read from the tag
	 * @throws labid.reader.RFReaderException If unable to read a tag.
	 */
	public byte[] ReadUltralight() throws RFReaderException
	{
		return this.ReadUltralight(0, MF_UL_SIZE);
	}

	/**
	 * Activates a Mifare Ultralight tag and reads the user data of its memory (blocks 4-15)
	 *
	 * @return Data read from the tag
	 * @throws labid.reader.RFReaderException If unable to read a tag.
	 */
	public byte[] ReadUltralightUserData() throws RFReaderException
	{
		return this.ReadUltralight(16, 48);
	}

	/**
	 * Activates a Mifare UltralightC tag and reads the user data of its memory (blocks 4-39)
	 * @return Data read from the tag.
	 * @throws RFReaderException If unable to read a tag.
	 */
	public byte[] ReadUltralightCUserData() throws RFReaderException
	{
		return this.ReadUltralightC(4, 36, false, true);
	}

	/**
	 * Counts bits set to 1 in a byte array
	 *
	 */
	private static int countOnes(long mask)
	{
		int ones = 0;
		long b;
		for (int i = 0; i < 64; i++)
		{
			b = (1L << i);
			if ((mask & b) != 0)
			{
				ones++;
			}
		}

		return ones;
	}

	private static int countOnes(short mask)
	{
		int ones = 0;
		for (int i = 0; i < 16; i++)
		{
			if ((mask & (1 << i)) != 0)
			{
				ones++;
			}
		}

		return ones;
	}

	/**
	 * Activates a Mifare Ultralight tag and writes its memory
	 *
	 * @param data Data to be written. Data length must match block_sel_mask.
	 * @param block_sel_mask Selects which blocks are to be written with a bit-wise mask.
	 */
	public void WriteUltralight(byte[] data, short block_sel_mask) throws RFReaderException
	{
		int nBlocks = countOnes(block_sel_mask);

		if (data.length != nBlocks * MF_UL_BLOCK_SIZE)
		{
			throw new MifareException("Data length non consistent with block_sel_mask");
		}

		byte[] cmd = new byte[4 + data.length];

		cmd[0] = MF_MACRO;
		cmd[1] = 0x21; //command code
		cmd[2] = (byte) (block_sel_mask & 0xFF);
		cmd[3] = (byte) ((block_sel_mask >> 8) & 0xFF);
		ByteUtils.copy(data, 0, cmd, 4, data.length);

		sendReceive(cmd, "Unable to write");

		this.lastDetectedUid = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, this.lastDetectedUid, 0, this.lastDetectedUid.length);
	}

	/**
	 * Activates a Mifare Ultralight or UltralightC tag and writes its memory.
	 * @param data Data to be written. Data length must match nBlocks.
	 * @param firstBlock 0-based index of the first block to be written.
	 * @param nBlocks Number of blocks (of 4 bytes each) to be written.
	 * @param skipActivation Skips the activation sequence before writing.
	 * @param rfReset Runs a RF reset before writing.
	 * @throws RFReaderException In case of write error
	 */
	public void WriteUltralight(byte[] data, int firstBlock, int nBlocks, boolean skipActivation, boolean rfReset)
			throws RFReaderException
	{
		if (data.length != nBlocks * MF_UL_BLOCK_SIZE)
		{
			throw new MifareException("Data length non consistent with nBlocks parameter");
		}

		byte[] cmd = new byte[5 + data.length];

		cmd[0] = MF_MACRO;
		cmd[1] = 0x23; //command code
		cmd[2] = ByteUtils.composeByte(skipActivation, rfReset, false, false, false, false, false, false);
		cmd[3] = (byte) (firstBlock);
		cmd[4] = (byte) (nBlocks);

		ByteUtils.copy(data, 0, cmd, 5, data.length);

		sendReceive(cmd, "Unable to write");

		this.lastDetectedUid = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, this.lastDetectedUid, 0, this.lastDetectedUid.length);
	}

	/**
	 * Activates a Mifare Ultralight and writes data to the user data (Read/Write) area.
	 *
	 * @param data Data to be written. It must be shorter than 48 bytes. It can
	 * have any length, but it will be padded with zeroes until its length is multiple of 4
	 */
	public void WriteUltralightUserData(byte[] data) throws RFReaderException
	{
		int len = data.length;
		if (len > 48)
		{
			throw new MifareException("User data too long");
		}

		// calulate number of necessary blocks
		int nBlocks = len / MF_UL_BLOCK_SIZE;

		// if data length is not multiple of 4 (UL block size), data is padded
		if (len % MF_UL_BLOCK_SIZE > 0)
		{
			nBlocks++;
			byte[] tmp = new byte[nBlocks * MF_UL_BLOCK_SIZE];
			ByteUtils.copy(data, tmp);
			data = tmp;
		}

		// compose the proper block selection mask, from the first user block (4)
		short mask = 0;
		for (int i = 4; i < nBlocks + 4; i++)
		{
			mask |= (short) (1 << i);
		}

		this.WriteUltralight(data, mask);
	}

	/**
	 * Activates a Mifare Ultralight or UltralightC tag and writes data to the
	 * user data (Read/Write) area.
	 * @param data Data to be written. It must be shorter than 48 bytes for Ultralight
	 * tags and shorter than 144 for UltralightC tags. It can have any length, but
	 * it will be padded with zeroes until its length is multiple of 4.
	 * @throws RFReaderException
	 */
	public void WriteUltralightCUserData(byte[] data) throws RFReaderException
	{
		int len = data.length;
		if (len > 144)
		{
			throw new MifareException("User data too long");
		}

		// calulate number of necessary blocks
		int nBlocks = len / MF_UL_BLOCK_SIZE;

		// if data length is not multiple of 4 (UL block size), data is padded
		if (len % MF_UL_BLOCK_SIZE > 0)
		{
			nBlocks++;
			byte[] tmp = new byte[nBlocks * MF_UL_BLOCK_SIZE];
			ByteUtils.copy(data, tmp);
			data = tmp;
		}

		// write data starting from block 4
		this.WriteUltralight(data, 4, nBlocks, false, true);
	}

	/**
	 * Activates, authenticates and reads part of a sector of a Mifare 1K/4K tag,
	 * according to parameters
	 *
	 * @param sector Index of the sector to be read (1K: 0-16; 4K:0-39)
	 * @param useAccessKey Specifies if an access key is to be used. If false,
	 * the default 0xFF key will be used
	 * @param useKeyB Specifies if the authentication key is KeyB or, if false, KeyA
	 * @param useInternalKey Specifies if key is passed as a parameter or if it is
	 * stored in internal EEPROM of the reader
	 * @param keyIndex If useInternalKey parameter is true, this parameter specifies
	 * the index of the key stored in internal EEPROM of the reader. Otherwise this parameter
	 * is ignored
	 * @param key If useInternalKey parameter is false, this parameter must be a
	 * 6 bytes long array containing the access key. Otherwise it is ignored and can be null
	 * @param block_sel_mask Selects which blocks of the sector are to be read: it is a bitwise
	 * coded mask LSB->MSB. Mifare 1K tags accept only 4 less significant bits of the first byte.
	 *
	 * @return Selected data read from a transponder
	 */
	public byte[] ReadSector(int sector, boolean useAccessKey, boolean useKeyB, boolean useInternalKey,
			int keyIndex, byte[] key, short block_sel_mask) throws RFReaderException
	{
		byte flags = ByteUtils.composeByte(false, false, false, false, useInternalKey, false,
				useKeyB, useAccessKey);

		int cmdlen = 6;

		if (useAccessKey)
		{
			if (useInternalKey)
			{
				if (keyIndex > 31)
				{
					throw new MifareException("Key index must be lesser than 32");
				}
				cmdlen++;
			}
			else
			{
				if (key.length != 6)
				{
					throw new MifareException("Mifare keys must be 6 bytes long");
				}
				cmdlen += 6;
			}
		}

		byte[] cmd = new byte[cmdlen];

		int i = 0;
		cmd[i++] = MF_MACRO;
		cmd[i++] = 0x42; //command code
		cmd[i++] = (byte) sector;
		cmd[i++] = flags;
		cmd[i++] = (byte) (block_sel_mask & 0xFF);
		cmd[i++] = (byte) ((block_sel_mask >> 8) & 0xFF);
		if (useAccessKey)
		{
			if (useInternalKey)
			{
				cmd[i++] = (byte) keyIndex;
			}
			else
			{
				ByteUtils.copy(key, 0, cmd, i, 6);
			}
		}

		sendReceive(cmd, "Unable to read", 5);

		byte[] result = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, result, 0, recv_buf[5]);
		return result;
	}

	/**
	 * Activates, authenticates and writes part of a sector of a Mifare 1K/4K tag,
	 * according to parameters
	 *
	 * @param data Data to be written
	 * @param sector Index of the sector to be written (1K: 0-16; 4K:0-39)
	 * @param useAccessKey Specifies if an access key is to be used. If false,
	 * the default 0xFF key will be used
	 * @param useKeyB Specifies if the authentication key is KeyB or, if false, KeyA
	 * @param useInternalKey Specifies if key is passed as a parameter or if it is
	 * stored in internal EEPROM of the reader
	 * @param keyIndex If useInternalKey parameter is true, this parameter specifies
	 * the index of the key stored in internal EEPROM of the reader. Otherwise this parameter
	 * is ignored
	 * @param key If useInternalKey parameter is false, this parameter must be a
	 * 6 bytes long array containing the access key. Otherwise it is ignored and can be null
	 * @param block_sel_mask Selects which blocks of the sector are to be read: it is a bitwise
	 * coded mask LSB->MSB. Mifare 1K tags accept only 4 less significant bits of the first byte.
	 *
	 */
	public void WriteSector(byte[] data, int sector, boolean useAccessKey, boolean useKeyB, boolean useInternalKey,
			int keyIndex, byte[] key, short block_sel_mask) throws RFReaderException
	{
		byte flags = ByteUtils.composeByte(false, false, false, false, useInternalKey, false,
				useKeyB, useAccessKey);

		int nBlocks = countOnes(block_sel_mask);
		int expectedDataLen = nBlocks * MF_BLOCK_SIZE;
		if (data.length < expectedDataLen)
		{
			throw new MifareException("Data size is not consitent with block selection mask");
		}

		int cmdlen = 6 + expectedDataLen;

		if (useAccessKey)
		{
			if (useInternalKey)
			{
				if (keyIndex > 31)
				{
					throw new MifareException("Key index must be lesser than 32");
				}
				cmdlen++;
			}
			else
			{
				if (key.length != 6)
				{
					throw new MifareException("Mifare keys must be 6 bytes long");
				}
				cmdlen += 6;
			}
		}

		byte[] cmd = new byte[cmdlen];

		int i = 0;
		cmd[i++] = MF_MACRO;
		cmd[i++] = 0x41; //command code
		cmd[i++] = (byte) sector;
		cmd[i++] = flags;
		cmd[i++] = (byte) (block_sel_mask & 0xFF);
		cmd[i++] = (byte) ((block_sel_mask >> 8) & 0xFF);
		if (useAccessKey)
		{
			if (useInternalKey)
			{
				cmd[i++] = (byte) keyIndex;
			}
			else
			{
				ByteUtils.copy(key, 0, cmd, i, 6);
				i += 6;
			}
		}

		ByteUtils.copy(data, 0, cmd, i, expectedDataLen);

		sendReceive(cmd, "Unable to write", 5);

		this.lastDetectedUid = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, this.lastDetectedUid, 0, this.lastDetectedUid.length);
	}

	/**
	 * Writes the sector trailers of a Mifare 1K/4K tag, according to parameters.
	 *
	 * @param sel_mask Bitwise coded mask for sector trailer selection, LSB->MSB.
	 * @param trailers 16 bytes long sector trailer contents.
	 */
	public void InitializeSectorTrailers(long sel_mask, byte[][] trailers) throws RFReaderException
	{
		int nSectors = countOnes(sel_mask);
		int i;

		if (nSectors != trailers.length)
		{
			throw new MifareException("Number of defined sector trailers is not consistent with selection mask");
		}

		for (i = 0; i < nSectors; i++)
		{
			if (trailers[i].length != MF_BLOCK_SIZE)
			{
				throw new MifareException("Sector trailers must be 16 bytes long");
			}
		}

		byte[] cmd = new byte[7 + nSectors * MF_BLOCK_SIZE];

		i = 0;
		cmd[i++] = MF_MACRO;
		cmd[i++] = 0x43; //command code
		cmd[i++] = (byte) (sel_mask & 0xFF);
		cmd[i++] = (byte) ((sel_mask >> 8) & 0xFF);
		cmd[i++] = (byte) ((sel_mask >> 16) & 0xFF);
		cmd[i++] = (byte) ((sel_mask >> 24) & 0xFF);
		cmd[i++] = (byte) ((sel_mask >> 32) & 0xFF);

		for (int j = 0; j < nSectors; j++)
		{
			ByteUtils.copy(trailers[j], 0, cmd, i, MF_BLOCK_SIZE);
			i += MF_BLOCK_SIZE;
		}

		sendReceive(cmd, "Unable to initialize sector trailers", 5);

		this.lastDetectedUid = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, this.lastDetectedUid, 0, this.lastDetectedUid.length);
	}

	public byte[] ExchangeBytes(byte[] send) throws RFReaderException
	{
		byte[] cmd = new byte[send.length + 3];

		cmd[0] = (byte) 0xA0;
		cmd[1] = (byte) 0xD1; //command code: exchange ISO14443-3
		cmd[2] = (byte) send.length;
		ByteUtils.copy(send, 0, cmd, 3, send.length);

		sendReceive(cmd, "Unable to transceive");

		byte[] result = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, result, 0, recv_buf[5]);

		return result;
	}

	static byte[] RotateRight(byte[] data)
	{
		byte[] result = new byte[data.length];

		//it is assumed that the byte order is big endian
		int i = 0;
		byte buffer = data[0];

		//decrease the position of every element in the array
		for (i = 0; i < data.length - 1; i++)
		{
			result[i] = data[i + 1];
		}

		//now put the initial first element to the end of the array
		result[data.length - 1] = buffer;

		return result;
	}

	static byte[] RotateLeft(byte[] data)
	{
		byte[] result = new byte[data.length];

		//it is assumed that the byte order is big endian
		int i = 0;

		//decrease the position of every element in the array
		for (i = 0; i < data.length - 1; i++)
		{
			result[i + 1] = data[i];
		}

		//now put the initial first element to the end of the array
		result[0] = data[data.length - 1];

		return result;
	}
	
	public boolean AuthenticateUltralightC(byte[] key) throws Exception
	{
		return AuthenticateISO(key, false);
	}

	boolean AuthenticateISO(byte[] rawkey16, boolean useISO14443A_4) throws Exception
	{
		byte[] cmd = new byte[]
		{
			0x1A, 0x00
		}; // authentication step1 request
		byte[] resp;
		byte[] RnA, RnB;
		Cipher tdes;

		if (rawkey16 == null)
		{
			throw new NullPointerException("Parameter key must be not null");
		}

		if (rawkey16.length != 16)
		{
			throw new ArrayIndexOutOfBoundsException("Parameter key must be 16 bytes long");
		}

		byte[] rawkey = new byte[24];
		ByteUtils.copy(rawkey16, rawkey);
		ByteUtils.copy(rawkey16, 0, rawkey, 16, 8);

		DESedeKeySpec keyspec = new DESedeKeySpec(rawkey);
		SecretKeyFactory keyfactory = SecretKeyFactory.getInstance("DESede");
		SecretKey key = keyfactory.generateSecret(keyspec);
		IvParameterSpec iv = new IvParameterSpec(new byte[8]);

		try
		{
			////////// Auth Step 1 ------------------------------------------

			// send authentication request
			resp = ExchangeBytes(cmd);

			//if everything went ok, copy RndB from recv_data to RnB_enc
			if (resp[0] == (byte)0xAF)
			{
				byte[] RnB_enc = new byte[8];
				ByteUtils.copy(resp, 1, RnB_enc, 0, 8);

				tdes = Cipher.getInstance("DESede/CBC/NoPadding");

				// set 3DES decryption; initvector (IV) initialize with zero
				tdes.init(Cipher.DECRYPT_MODE, key, iv);

				// decrypt the received random number RndB
				RnB = tdes.doFinal(RnB_enc, 0, RnB_enc.length);

				//copy the received cryptogram to the init vector for encryption
				iv = new IvParameterSpec(RnB_enc);
				tdes.init(Cipher.ENCRYPT_MODE, key, iv);


				////////// Auth Step 2 ---------------------------------------

				byte[] RnA_enc;

				// numero casuale
				RnA = new byte[8];
				Random rnd = new Random();
				rnd.nextBytes(RnA);

				// encrypt RnA
				RnA_enc = tdes.doFinal(RnA, 0, RnA.length);

				//copy the received cryptogram to the init vector for encryption
				iv = new IvParameterSpec(RnA_enc);
				tdes.init(Cipher.ENCRYPT_MODE, key, iv);

				// rotate RnB to the right
				RnB = RotateRight(RnB);

				//encrypt RnB
				RnB_enc = tdes.doFinal(RnB, 0, RnB.length);

				//copy the received cryptogram to the global init vector for decryption
				iv = new IvParameterSpec(RnB_enc);
				tdes.init(Cipher.DECRYPT_MODE, key, iv);

				// concatenate the encrypted numbers by copying them together into an array
				byte[] RnA_RnB_enc = ByteUtils.concat(RnA_enc, RnB_enc);

				// send the AuthStep2 command
				cmd = new byte[17];
				cmd[0] = (byte) 0xAF;
				ByteUtils.copy(RnA_RnB_enc, 0, cmd, 1, RnA_RnB_enc.length);

				resp = ExchangeBytes(cmd);

				// se l'autenticazione fallisce , il tag risponde solo "00"
				if (resp.length == 1)
				{
					return false;
				}

				byte[] RnA_rec_enc = new byte[8];
				ByteUtils.copy(resp, 1, RnA_rec_enc, 0, 8);

				//decrypt RnA'
				byte[] Rna_rec = tdes.doFinal(RnA_rec_enc, 0, 8);

				//now the crypto work is done, lets clean up...
				//tdes.Clear();

				// rotate RnA' from PICC to the left for comparison
				Rna_rec = RotateLeft(Rna_rec);

				// check if RnA and received Rna are equal. If so, authentication is successful!
				return ByteUtils.areEqual(RnA, Rna_rec);
			}
			else
			{
				throw new RFReaderException("Unable to authenticate: response from tag has a wrong header.");
			}
		}
		catch (Exception ex)
		{
			throw new RFReaderException("Unable to authenticate. " + ex.getMessage());
		}
	}
}

