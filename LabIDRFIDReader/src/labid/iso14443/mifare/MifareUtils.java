
package labid.iso14443.mifare;

import labid.comm.ByteUtils;

/**
* Provides some static utility methods for MIFARE cards handling.
*/
public class MifareUtils {
	private MifareUtils() {
		
	}
	
	/** 
	* Composes a MIFARE compliant sector trailer, according to passed parameters.
	* 
	* @param keyA Cryptography Key A
	* @param keyB Cryptography Key B
	* @param access Access permissions you want to set for the current sector.

*/
public static byte[] composeSectorTrailer(byte[] keyA, byte[] keyB, AccessPermission access) throws MifareException {
		if (keyA.length != 6)
			throw new MifareException("Key A must be 6 bytes long");
		
		if (keyB.length != 6)
			throw new MifareException("Key B must be 6 bytes long");
		
		byte[] accessBits ;
		
		try {
			accessBits = getAccessBytes(access);
		}
		catch (MifareException mfe) {
			throw new MifareException("Illegal access configuration");
		}
		
		byte[] trailer = new byte[16];
		ByteUtils.copy(keyA, 0, trailer, 0, 6);
		ByteUtils.copy(accessBits, 0, trailer, 6, 4);
		ByteUtils.copy(keyB, 0, trailer, 10, 6);
		
		return trailer;
	}
	
	/** 
	* Decodes a MIFARE compliant Sector Trailer in order to get the matching
	* Access permissions.
	* 
	* @param st 16 bytes long sector trailer.
	* @return An AccessPermission struct containing the access permissions

*/
public static AccessPermission getAccessPermissionsFromSectorTrailer(byte[] st) throws MifareException {
		if (st.length != 16)
			throw new MifareException("Sector trailer must be 16 bytes long");
		
		if (
		((byte)((~st[6] & 0xF0) >> 4) != (byte)(st[8] & 0x0F)) ||
		((byte)(~st[6] & 0x0F) != (byte)((st[7] & 0xF0) >> 4)) ||
		((byte)(~st[7] & 0x0F) != (byte)((st[8] & 0xF0) >> 4)) )
			
			throw new MifareException("Bad sector trailer format.");
		
		AccessPermission result = new AccessPermission();
		
		boolean[] c0 = new boolean[3];
		boolean[] c1 = new boolean[3];
		boolean[] c2 = new boolean[3];
		boolean[] c3 = new boolean[3];
		
		c0[0] = ByteUtils.getBit(st[7], 4);
		c0[1] = ByteUtils.getBit(st[8], 0);
		c0[2] = ByteUtils.getBit(st[8], 4);
		
		c1[0] = ByteUtils.getBit(st[7], 5);
		c1[1] = ByteUtils.getBit(st[8], 1);
		c1[2] = ByteUtils.getBit(st[8], 5);
		
		c2[0] = ByteUtils.getBit(st[7], 6);
		c2[1] = ByteUtils.getBit(st[8], 2);
		c2[2] = ByteUtils.getBit(st[8], 6);
		
		c3[0] = ByteUtils.getBit(st[7], 7);
		c3[1] = ByteUtils.getBit(st[8], 3);
		c3[2] = ByteUtils.getBit(st[8], 7);
		
		result.Block0 = getBlockAccessFromBits(c0);
		result.Block1 = getBlockAccessFromBits(c1);
		result.Block2 = getBlockAccessFromBits(c2);
		result.SectorTrailer = getSectorTrailerFromBits(c3);
		
		return result;
	}
	
	private static SectorTrailerAccess getSectorTrailerFromBits(boolean[] c) throws MifareException {
		SectorTrailerAccess result = new SectorTrailerAccess();
		byte cn;
		cn = ByteUtils.composeByte(c[2], c[1], c[0], false, false, false, false, false);
		
		switch (cn) {
			case 0:
				result.WriteKey_A = SectorTrailerAccess.Key_A;
				result.ReadAccessBits = SectorTrailerAccess.Key_A;
				result.WriteAccessBits = SectorTrailerAccess.Never;
				result.ReadKey_B = SectorTrailerAccess.Key_A;
				result.WriteKey_B = SectorTrailerAccess.Key_A;
				break;
			case 0x02:
				result.WriteKey_A = SectorTrailerAccess.Never;
				result.ReadAccessBits = SectorTrailerAccess.Key_A;
				result.WriteAccessBits = SectorTrailerAccess.Never;
				result.ReadKey_B = SectorTrailerAccess.Key_A;
				result.WriteKey_B = SectorTrailerAccess.Never;
				break;
			case 0x04:
				result.WriteKey_A = SectorTrailerAccess.Key_B;
				result.ReadAccessBits = SectorTrailerAccess.Key_A_or_B;
				result.WriteAccessBits = SectorTrailerAccess.Never;
				result.ReadKey_B = SectorTrailerAccess.Never;
				result.WriteKey_B = SectorTrailerAccess.Key_B;
				break;
			case 0x06:
				result.WriteKey_A = SectorTrailerAccess.Never;
				result.ReadAccessBits = SectorTrailerAccess.Key_A_or_B;
				result.WriteAccessBits = SectorTrailerAccess.Never;
				result.ReadKey_B = SectorTrailerAccess.Never;
				result.WriteKey_B = SectorTrailerAccess.Never;
				break;
			case 0x01:
				result.WriteKey_A = SectorTrailerAccess.Key_A;
				result.ReadAccessBits = SectorTrailerAccess.Key_A;
				result.WriteAccessBits = SectorTrailerAccess.Key_A;
				result.ReadKey_B = SectorTrailerAccess.Key_A;
				result.WriteKey_B = SectorTrailerAccess.Key_A;
				break;
			case 0x03:
				result.WriteKey_A = SectorTrailerAccess.Key_B;
				result.ReadAccessBits = SectorTrailerAccess.Key_A_or_B;
				result.WriteAccessBits = SectorTrailerAccess.Key_B;
				result.ReadKey_B = SectorTrailerAccess.Never;
				result.WriteKey_B = SectorTrailerAccess.Key_B;
				break;
			case 0x05:
				result.WriteKey_A = SectorTrailerAccess.Never;
				result.ReadAccessBits = SectorTrailerAccess.Key_A_or_B;
				result.WriteAccessBits = SectorTrailerAccess.Key_B;
				result.ReadKey_B = SectorTrailerAccess.Never;
				result.WriteKey_B = SectorTrailerAccess.Never;
				break;
			case 0x07:
				result.WriteKey_A = SectorTrailerAccess.Never;
				result.ReadAccessBits = SectorTrailerAccess.Key_A_or_B;
				result.WriteAccessBits = SectorTrailerAccess.Never;
				result.ReadKey_B = SectorTrailerAccess.Never;
				result.WriteKey_B = SectorTrailerAccess.Never;
				break;
			default:
				throw new MifareException("Illegal data block configuration");
		}
		
		return result;
	}
	
	private static BlockAccess getBlockAccessFromBits(boolean[] c) throws MifareException {
		BlockAccess result = new BlockAccess();
		byte cn;
		cn = ByteUtils.composeByte(c[0], c[1], c[2], false, false, false, false, false);
		
		switch (cn) {
			case 0:
				result.Read = BlockAccess.Key_A_or_B;
				result.Write = BlockAccess.Key_A_or_B;
				result.Increment = BlockAccess.Key_A_or_B;
				result.Decrement = BlockAccess.Key_A_or_B;
				break;
			case 0x02:
				result.Read = BlockAccess.Key_A_or_B;
				result.Write = BlockAccess.Never;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Never;
				break;
			case 0x04:
				result.Read = BlockAccess.Key_A_or_B;
				result.Write = BlockAccess.Key_B;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Never;
				break;
			case 0x06:
				result.Read = BlockAccess.Key_A_or_B;
				result.Write = BlockAccess.Key_B;
				result.Increment = BlockAccess.Key_B;
				result.Decrement = BlockAccess.Key_A_or_B;
				break;
			case 0x01:
				result.Read = BlockAccess.Key_A_or_B;
				result.Write = BlockAccess.Never;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Key_A_or_B;
				break;
			case 0x03:
				result.Read = BlockAccess.Key_B;
				result.Write = BlockAccess.Key_B;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Never;
				break;
			case 0x05:
				result.Read = BlockAccess.Key_B;
				result.Write = BlockAccess.Never;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Never;
				break;
			case 0x07:
				result.Read = BlockAccess.Never;
				result.Write = BlockAccess.Never;
				result.Increment = BlockAccess.Never;
				result.Decrement = BlockAccess.Never;
				break;
			default:
				throw new MifareException("Illegal data block configuration");
		}
		return result;
	}
	
	/** 
	* Composes a 16 bytes long data block according to MIFARE value format.
	* 
	* @param val The signed 32 bit integer you want to store in a data block. 
	* @param addr Index of the block which will store the value (optional).

*/
public static byte[] composeValue(int val, int addr) {
		byte[] data = new byte[4];
		data[0] = (byte)(val & 0xFF);
		data[1] = (byte)((val >> 8) & 0xFF);
		data[2] = (byte)((val >> 16) & 0xFF);
		data[3] = (byte)((val >> 24) & 0xFF);
		
		byte[] result = new byte[16];
		result[0] = result[8] = data[0];
		result[1] = result[9] = data[1];
		result[2] = result[10] = data[2];
		result[3] = result[11] = data[3];
		result[4] = (byte)(~data[0]);
		result[5] = (byte)(~data[1]);
		result[6] = (byte)(~data[2]);
		result[7] = (byte)(~data[3]);
		
		result[12] = result[14] = (byte)addr;
		result[13] = result[15] = (byte)(~addr);
		
		return result;
	}
	
	/** 
	* Gets the integer value represented in 16 bytes according to the MIFARE
	* encoding format.
	* 
	* @param data 16 bytes long data block content.

*/
public static int decodeValue(byte[] data) throws MifareException {
		if (data.length != 16)
			throw new MifareException("Data block is not 16 bytes long");
		
		int result;
		if (
		(data[0] == data[8]) && (data[0] == (byte)~data[4]) &&
		(data[1] == data[9]) && (data[1] == (byte)~data[5]) &&
		(data[2] == data[10]) && (data[2] == (byte)~data[6]) &&
		(data[3] == data[11]) && (data[3] == (byte)~data[7]) &&
		(data[12] == data[14]) && (data[12] == (byte)~data[13]) &&
		(data[12] == (byte)~data[15]) )
			result = (data[3] << 24) + (data[2] << 16) + (data[1] << 8) + data[0];
		else throw new MifareException("Not a valid MIFARE value");
		
		return result;
	}
	
	/** 
	* Calculates the Access Bytes to write to Sector Trailer data block
	* according to current block access settings.
	* 
	* @param ap The AccessPermission struct which represents the
	* desired access permissions.
	* @return 4 bytes with the MIFARE combination of access bits.
	* @throws MifareException If current block access settings are

*/
public static byte[] getAccessBytes(AccessPermission ap) throws MifareException {
		boolean c10, c20, c30, c11, c12, c13, c21, c22, c23, c31, c32, c33;
		boolean[] temp = new boolean[3];
		
		temp = getBitsForSectorTrailerAccess(ap.SectorTrailer);
		c13 = temp[0];
		c23 = temp[1];
		c33 = temp[2];
		
		temp = getBitsForDataBlockAccess(ap.Block0);
		c10 = temp[0];
		c20 = temp[1];
		c30 = temp[2];
		
		temp = getBitsForDataBlockAccess(ap.Block1);
		c11 = temp[0];
		c21 = temp[1];
		c31 = temp[2];
		
		temp = getBitsForDataBlockAccess(ap.Block2);
		c12 = temp[0];
		c22 = temp[1];
		c32 = temp[2];
		
		byte[] result = new byte[4];
		result[0] = ByteUtils.composeByte(!c10, !c11, !c12, !c13, !c20, !c21, !c22, !c23);
		result[1] = ByteUtils.composeByte(!c30, !c31, !c32, !c33,  c10,  c11,  c12,  c13);
		result[2] = ByteUtils.composeByte( c20,  c21,  c22,  c23,  c30,  c31,  c32,  c33);
		result[3] = 0;
		
		return result;
	}
	
	private static boolean[] getBitsForDataBlockAccess(BlockAccess ax) throws MifareException {
		boolean[] c = new boolean[3];
		
		if (ax.Read == BlockAccess.Key_A_or_B &&
		ax.Write == BlockAccess.Key_A_or_B &&
		ax.Increment == BlockAccess.Key_A_or_B &&
		ax.Decrement == BlockAccess.Key_A_or_B ) {
			c[0] = false;
			c[1] = false;
			c[2] = false;
		}
		else if (ax.Read == BlockAccess.Key_A_or_B &&
		ax.Write == BlockAccess.Never &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Never ) {
			c[0] = false;
			c[1] = true;
			c[2] = false;
		}
		else if (ax.Read == BlockAccess.Key_A_or_B &&
		ax.Write == BlockAccess.Key_B &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Never ) {
			c[0] = true;
			c[1] = false;
			c[2] = false;
		}
		else if (ax.Read == BlockAccess.Key_A_or_B &&
		ax.Write == BlockAccess.Key_B &&
		ax.Increment == BlockAccess.Key_B &&
		ax.Decrement == BlockAccess.Key_A_or_B ) {
			c[0] = true;
			c[1] = true;
			c[2] = false;
		}
		else if (ax.Read == BlockAccess.Key_A_or_B &&
		ax.Write == BlockAccess.Never &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Key_A_or_B ) {
			c[0] = false;
			c[1] = false;
			c[2] = true;
		}
		else if (ax.Read == BlockAccess.Key_B &&
		ax.Write == BlockAccess.Key_B &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Never ) {
			c[0] = false;
			c[1] = true;
			c[2] = true;
		}
		else if (ax.Read == BlockAccess.Key_B &&
		ax.Write == BlockAccess.Never &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Never ) {
			c[0] = true;
			c[1] = false;
			c[2] = true;
		}
		else if (ax.Read == BlockAccess.Never &&
		ax.Write == BlockAccess.Never &&
		ax.Increment == BlockAccess.Never &&
		ax.Decrement == BlockAccess.Never ) {
			c[0] = true;
			c[1] = true;
			c[2] = true;
		}
		else
			throw new MifareException();
		
		return c;
	}
	
	private static boolean[] getBitsForSectorTrailerAccess(SectorTrailerAccess ax) throws MifareException {
		boolean[] c = new boolean[3];
		
		if (ax.WriteKey_A == SectorTrailerAccess.Key_A &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A &&
		ax.WriteAccessBits == SectorTrailerAccess.Never &&
		ax.ReadKey_B == SectorTrailerAccess.Key_A &&
		ax.WriteKey_B == SectorTrailerAccess.Key_A) {
			c[0] = false;
			c[1] = false;
			c[2] = false;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Never &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A &&
		ax.WriteAccessBits == SectorTrailerAccess.Never &&
		ax.ReadKey_B == SectorTrailerAccess.Key_A &&
		ax.WriteKey_B == SectorTrailerAccess.Never) {
			c[0] = false;
			c[1] = true;
			c[2] = false;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Key_B &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A_or_B &&
		ax.WriteAccessBits == SectorTrailerAccess.Never &&
		ax.ReadKey_B == SectorTrailerAccess.Never &&
		ax.WriteKey_B == SectorTrailerAccess.Key_B) {
			c[0] = true;
			c[1] = false;
			c[2] = false;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Never &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A_or_B &&
		ax.WriteAccessBits == SectorTrailerAccess.Never &&
		ax.ReadKey_B == SectorTrailerAccess.Never &&
		ax.WriteKey_B == SectorTrailerAccess.Never) {
			c[0] = true;
			c[1] = true;
			c[2] = false;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Key_A &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A &&
		ax.WriteAccessBits == SectorTrailerAccess.Key_A &&
		ax.ReadKey_B == SectorTrailerAccess.Key_A &&
		ax.WriteKey_B == SectorTrailerAccess.Key_A) {
			c[0] = false;
			c[1] = false;
			c[2] = true;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Key_B &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A_or_B &&
		ax.WriteAccessBits == SectorTrailerAccess.Key_B &&
		ax.ReadKey_B == SectorTrailerAccess.Never &&
		ax.WriteKey_B == SectorTrailerAccess.Key_B) {
			c[0] = false;
			c[1] = true;
			c[2] = true;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Never &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A_or_B &&
		ax.WriteAccessBits == SectorTrailerAccess.Key_B &&
		ax.ReadKey_B == SectorTrailerAccess.Never &&
		ax.WriteKey_B == SectorTrailerAccess.Never) {
			c[0] = true;
			c[1] = false;
			c[2] = true;
		}
		else if (ax.WriteKey_A == SectorTrailerAccess.Never &&
		ax.ReadAccessBits == SectorTrailerAccess.Key_A_or_B &&
		ax.WriteAccessBits == SectorTrailerAccess.Never &&
		ax.ReadKey_B == SectorTrailerAccess.Never &&
		ax.WriteKey_B == SectorTrailerAccess.Never) {
			c[0] = true;
			c[1] = true;
			c[2] = true;
		}
		else
			throw new MifareException();
		
		return c;
	}	
}