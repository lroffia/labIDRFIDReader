package labid.iso15693.icode;

import labid.comm.ByteUtils;
import labid.comm.CableStream;
import labid.iso15693.ISO15693Reader;
import labid.reader.RFReaderException;

/**
 * This class inherits from ISO15693Reader and provides methods for using custom commands
 * supported by NXP chips ICode SLI-S and SLI-L.
 * @author Daniele
 */
public class ICodeReader extends ISO15693Reader {

	/**
	 * Creates a new ICodeReader object.
	 */
	public ICodeReader() {
		super();
	}

	/**
	 * Creates a new ICodeReader object connected through a CableStream object
	 * @param stream Communication stream
	 */
	public ICodeReader(CableStream stream) {
		super(stream);
	}

	protected byte[] getRandomNumberBytes(byte[] uid)
			throws RFReaderException {
		int cmdlen;
		byte mode;

		// in non addressed mode the UID is not transmitted. this is used for privacy mode.
		if (uid == null) {
			cmdlen = 4;
			mode = (byte) 0x80; // normal mode, non addressed
		} else {
			cmdlen = 12;
			mode = (byte) 0xA0; // normal | addressed mode
		}

		byte[] cmd = new byte[cmdlen];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = mode;
		cmd[2] = (byte) 0xB2; //command code
		cmd[3] = 0x04; //philips manufacturer code

		if (uid != null) {
			ByteUtils.copy(uid, 0, cmd, 4, 8);
		}

		sendReceive(cmd, "Could not get random number");

		//Notify();
		byte[] rnd = new byte[2];
		rnd[0] = recv_buf[5];
		rnd[1] = recv_buf[6];
		return rnd;
	}

	/**
	 * This command is required to receive a random number from the IC. This number is required for
	 * Set Password command.
	 * @param uid Serial number of the addressed tag. Can be null if you request a Privacy password
	 * @return A random number sent by the IC
	 * @throws labid.reader.RFReaderException
	 */
	public int getRandomNumber(byte[] uid)
			throws RFReaderException {
		byte[] rnd;
		rnd = this.getRandomNumberBytes(uid);
		return (rnd[0] & 0xFF) + ((rnd[1] & 0xFF) << 8);
	}

	/**
	 * With this command the reader gets access to the different protected functionalities.
	 * This command has to be executed just once for the related password if the tag is powered.
	 * <i>Note: the necessary GetRandomNumber command is automatically executed.</i>
	 * @param uid Serial number of the addressed tag. Can be null only if the password type is Privacy
	 * @param pwdID Specifies which password type is to be used
	 * @param pwd 4 bytes long password
	 * @throws labid.reader.RFReaderException
	 */
	public void setPassword(byte[] uid, PasswordIdentifier pwdID, byte[] pwd)
			throws RFReaderException {
		if (pwd.length != 4) {
			throw new RFReaderException("ICode password must be 4 bytes long");
		}

		byte[] rnd;
		int cmdlen, k = 0;
		byte mode;

		rnd = this.getRandomNumberBytes(uid);

		// in non addressed mode the UID is not transmitted. this is used for privacy mode.
		if (uid == null) {
			cmdlen = 9;
			mode = (byte) 0x80; // normal mode, non addressed
		} else {
			cmdlen = 17;
			mode = (byte) 0xA0; // normal | addressed mode
		}

		byte[] cmd = new byte[cmdlen];
		cmd[k++] = (byte) 0xB1; //control byte: iso command custom
		cmd[k++] = mode;
		cmd[k++] = (byte) 0xB3; //command code
		cmd[k++] = 0x04; //philips manufacturer code

		if (uid != null) {
			ByteUtils.copy(uid, 0, cmd, 4, 8);
			k += 8;
		}

		cmd[k++] = pwdID.byteValue();
		cmd[k++] = (byte) (pwd[0] ^ rnd[0]);
		cmd[k++] = (byte) (pwd[1] ^ rnd[1]);
		cmd[k++] = (byte) (pwd[2] ^ rnd[0]);
		cmd[k++] = (byte) (pwd[3] ^ rnd[1]);

		sendReceive(cmd, "Could not set password");

	//Notify();
	}

	/**
	 *  This method writes a new password into the related memory, if the related old password
	 * has already been transmitted before and the password is not locked.
	 * @param uid Serial number of the addressed tag
	 * @param pwdID Specifies which password type is to be used
	 * @param pwd 4 bytes long password
	 * @throws labid.reader.RFReaderException
	 */
	public void writePassword(byte[] uid, PasswordIdentifier pwdID, byte[] pwd)
			throws RFReaderException {
		if (pwd.length != 4) {
			throw new RFReaderException("ICode password must be 4 bytes long");
		}

		byte[] cmd = new byte[17];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB4; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);
		cmd[12] = pwdID.byteValue();
		cmd[13] = pwd[0];
		cmd[14] = pwd[1];
		cmd[15] = pwd[2];
		cmd[16] = pwd[3];

		sendReceive(cmd, "Could not write password");

	//Notify();
	}

	/**
	 * This method locks the addressed password if the selected password has already been
	 * transmitted before. <b>A locked password cannot be changed anymore.</b>
	 * @param uid Serial number of the addressed tag
	 * @param pwdID Specifies which password type is to be used
	 * @throws labid.reader.RFReaderException
	 */
	public void lockPassword(byte[] uid, PasswordIdentifier pwdID)
			throws RFReaderException {
		byte[] cmd = new byte[13];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB5; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);
		cmd[12] = pwdID.byteValue();

		sendReceive(cmd, "Could not lock password");

	//Notify();
	}

	/**
	 * This method tells the tag that the Read and Write passwords are both required
	 * to get access to password protected blocks. This mode can be enabled if both
	 * Read and Write password have been transmitted before with a SetPassword command.
	 * @param uid Serial number of the addressed tag
	 * @throws labid.reader.RFReaderException
	 */
	public void enable64bitPasswordProtection(byte[] uid)
			throws RFReaderException {
		byte[] cmd = new byte[12];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xBB; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);

		sendReceive(cmd, "Could not enable 64bit password protection");

	//Notify();
	}

	/**
	 * This method protects a page, under the following conditions: <br/>
	 * <ul>
	 *		<li>the related passwords (Read and/or Write) have been transmitted before (not required
	 *		if the page is public)</li>
	 *		<li>the addressed page protection condition is not locked</li>
	 * </ul>
	 * @param uid Serial number of the addressed tag
	 * @param page 0-based index of the addressed page
	 * @param protection The new protection condition for the addressed page
	 * @throws labid.reader.RFReaderException
	 */
	public void protectPage(byte[] uid, int page, ProtectionStatus protection)
			throws RFReaderException {
		byte[] cmd = new byte[14];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB6; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);
		cmd[12] = (byte) (page & 0xFF);
		cmd[13] = protection.byteValue();


		sendReceive(cmd, "Could not protect page");

	//Notify();
	}

	/**
	 * Locks the Page Protection condition status of the related page, if the related password
	 * (read and/or write) have been transmitted before (unless the page was public).
	 * <b>This command is irreversible</b>
	 * @param uid Serial number of the addressed tag
	 * @param page 0-based index of the addressed page
	 * @throws labid.reader.RFReaderException
	 */
	public void lockPageProtection(byte[] uid, int page)
			throws RFReaderException {
		byte[] cmd = new byte[13];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB7; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);
		cmd[12] = (byte) (page & 0xFF);

		sendReceive(cmd, "Could not lock page protection condition");

	//Notify();
	}

	/**
	 * Gets the protection status of the requested blocks. Each byte has the following meaning: <br/>
	 * b1 - block write-locked by ISO LockBlock command <br/>
	 * b2 - read password protection enabled<br/>
	 * b3 - write password protection enabled<br/>
	 * b4 - page protection status locked<br/>
	 * b5-b8 not used
	 * @param uid Serial number of the addressed tag
	 * @param firstBlock 0-based index of the first requested block
	 * @param nBlocks Number of requested blocks
	 * @return An array of nBlocks bytes, each one representing the protection status of a block
	 * @throws labid.reader.RFReaderException
	 */
	public byte[] getMultipleBlockProtectionStatus(byte[] uid, int firstBlock, int nBlocks)
			throws RFReaderException {
		byte[] cmd = new byte[14];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB8; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);
		cmd[12] = (byte) (firstBlock & 0xFF);
		cmd[13] = (byte) (nBlocks & 0xFF);

		sendReceive(cmd, "Could get multiple block protection status");

		byte[] result = new byte[nBlocks];
		ByteUtils.copy(recv_buf, 5, result, 0, nBlocks);
		return result;
	}

	/**
	 * Destroys the tag if the Destroy password has been sent before with a SetPassword command.
	 * <b>This command is irreversible and the tag will never respond to any command again</b>
	 * @param uid Serial number of the addressed tag
	 * @throws labid.reader.RFReaderException
	 */
	public void destroy(byte[] uid)
			throws RFReaderException {
		byte[] cmd = new byte[12];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xB9; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);

		sendReceive(cmd, "Could not destroy tag");

	//Notify();
	}

	/**
	 * In Privacy mode the tag will not respond to any command except GetRandomNumber and SetPassword.
	 * To get out from Privacy Mode the valid Privacy Password has to be transmitted with the 
	 * SetPassword command. To disable privacy, an all-zeroes privacy password must be set with 
	 * the WritePassword command.
	 * @param uid Serial number of the addressed tag
	 * @throws labid.reader.RFReaderException
	 */
	public void enablePrivacyMode(byte[] uid)
			throws RFReaderException {
		byte[] cmd = new byte[12];
		cmd[0] = (byte) 0xB1; //control byte: iso command custom
		cmd[1] = (byte) 0xA0; //normal | addressed mode
		cmd[2] = (byte) 0xBA; //command code
		cmd[3] = 0x04; //philips manufacturer code
		ByteUtils.copy(uid, 0, cmd, 4, 8);

		sendReceive(cmd, "Could not enable privacy");

	//Notify();
	}
}
