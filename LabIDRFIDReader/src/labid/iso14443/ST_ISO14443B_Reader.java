/*
 * ST_ISO14443B_Reader.java
 *
 * Created on 27 settembre 2005, 10.08
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package labid.iso14443;

import labid.comm.ByteUtils;
import labid.comm.CableStream;
import labid.reader.LabIdReader;
import labid.reader.RFReaderException;

/**
 *
 * @author Daniele
 */
public class ST_ISO14443B_Reader  extends LabIdReader {
	
	protected byte chip_id;
	private static final byte ISO14443B_CUSTOM = (byte)0xC1;
	private static final byte ST = 0x02;
	private boolean isSRIX = false;
	
	/** Creates a new instance of ST_ISO14443B_Reader */
	public ST_ISO14443B_Reader() {
		super();
	}
	
	/** Instantiates a new object connected through a SerialStream object
	 *
	 * @param stream Communication stream.
	 */
	public ST_ISO14443B_Reader(CableStream stream) {
		super(stream);
	}
	
	/**
	 * Returns the CHIP_ID value of the last selected SR176 transponder.
	 */
	public byte getChipID() {
		return this.chip_id;
	}
	
	/**
	 * Tells if the last transponder successfully detected with ReadUID() is ST SRIX or SR.
	 */
	public boolean isLastSRIX() {
		return this.isSRIX;
	}
	
	/**
	 * Initiates and Selects a ST SR176 transponder. You can run read/write
	 * operations only on previously selected transponder. If selection is
	 * successful, you can get the CHIP_ID value by invoking {@link #getChipID}.
	 *
	 * @return  True if a transponder was successfully selected. Else it
	 * returns false.
	 */
	public boolean Select() throws RFReaderException {
		byte[] cmd = new byte[3];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = 0x0E;
		
		try {
			send(cmd);
			receive();
		} catch (java.io.IOException ioe) {
			throw new RFReaderException(errMsg("Serial communication problem"));
		}
		
		if (recv_buf[4] == 0) {
			this.chip_id = recv_buf[5];
			return true;
		} else
			return false;
	}
	
	/**
	 * Reads some blocks from the memory of the selected transponder.
	 *
	 * @param firstBlock 0 based index of the first block to be read.
	 * @param nBlocks Number of blocks to be read.
	 * @return  The content of the blocks.
	 * @throws labid.reader.RFReaderException If unable to perform command.
	 */
	public byte[] Read(int firstBlock, int nBlocks) throws RFReaderException {
		byte[] cmd = new byte[5];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = (byte)0x88;
		cmd[3] = (byte)(firstBlock & 0xFF);
		cmd[4] = (byte)(nBlocks & 0xFF);
		
		sendReceive(cmd, "Unable to read blocks.");
		
		int respLen = recv_buf[5] * nBlocks; //DBsize * nBlocks
		byte[] result = new byte[respLen];
		ByteUtils.copy(recv_buf, 6, result, 0, respLen);
		
		return result;
	}
	
	/**
		* Reads the UID of the selected transponder. It may be a SRIX4K or a SR176.
		* @return The UID or null if unable to read it.
		* @throws RFReaderException If unable to perform command.
	 */
		public byte[] ReadUID() throws RFReaderException
		{
			byte[] uid;

			uid = this.GetSRIX4KUid();
			if (uid == null)
				uid = GetSR176Uid();
			
			return uid;
		}
	
	/**
	 * Reads the UID of ST SRIX4K transponders, which is not stored in the data blocks.
	 * This command is not available on SR176 transponders.
	 * @return  The UID of the selected transponder.
	 */
	public byte[] GetUid() throws RFReaderException {
		
		byte[] cmd = new byte[3];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = 0x0B;
		
		sendReceive(cmd, "Unable to get uid.", recv_buf[5]);
		
		byte[] uid = new byte[recv_buf[5]];
		ByteUtils.copy(recv_buf, 6, uid, 0, recv_buf[5]);
		
		return uid;
	}

	/**
		* Writes some blocks of the memory of the selected transponder. SR transponders have 
		* 2 bytes per block, while SRIX have 4. This command tries for both types.
		* @param firstBlock 0-based index of the first block to be written.
		* @param nBlocks Number of blocks to be written.
		* @param data Data to be written. If length of this buffer is not
		* consistent with nBlocks, data will be truncated or filled with 0s.
		* @throws RFReaderException If unable to perform command.
	 */
		public void Write(int firstBlock, int nBlocks, byte[] data) throws RFReaderException
		{
			if (this.isSRIX)
			{
				try
				{
					// se � un SRIX uso blockSize = 4
					this.writeST(firstBlock, nBlocks, data, 4);
				}
				catch (RFReaderException e)
				{
					// riprovo con SR -> blockSize = 2
					this.writeST(firstBlock, nBlocks, data, 2);
					this.isSRIX = false;
				}
			}
			else
			{
				try
				{
					// se � un SR uso blockSize = 2
					this.writeST(firstBlock, nBlocks, data, 2);
				}
				catch (RFReaderException e)
				{
					// riprovo con SRIX -> blockSize = 4
					this.writeST(firstBlock, nBlocks, data, 4);
					this.isSRIX = true;
				}
			}
		}
		
		protected void writeST(int firstBlock, int nBlocks, byte[] data, int blockSize) throws RFReaderException 
		{
			int datalen = nBlocks * blockSize;
			byte[] cmd = new byte[6 + datalen];

			cmd[0] = ISO14443B_CUSTOM;
			cmd[1] = ST;
			cmd[2] = (byte)0x89;
			cmd[3] = (byte)(firstBlock & 0xFF);
			cmd[4] = (byte)(nBlocks & 0xFF);
			cmd[5] = (byte)blockSize;
			ByteUtils.copy(data, 0, cmd, 6, datalen);

			sendReceive(cmd, "Unable to write blocks.", recv_buf[5] & 0xFF );
		}
	
	/**
	 * Ends the communication with the selected transponder: it is not selected
	 * anymore. As the transponder does not send a response, this is assumed
	 * as always successful by the reader.
	 *
	 * @throws RFReaderException If unable to perform command.
	 */
	public void Completion() throws RFReaderException {
		byte[] cmd = new byte[3];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = 0x0F;
		
		sendReceive(cmd, "Unable to perform completion.");
	}
	
	/**
	 * Locks blocks of the selected transponder.
	 *
	 * @param lockReg By setting to 1 bits of this
	 * bit-wise coded parameter, you can specify which couples of
	 * blocks are to be locked. <br/>
	 * <table border="1">
	 *		<tr>
	 *			<td>Blocks</td>
	 *			<td>14-15</td><td>12-13</td><td>10-11</td><td>8-9</td><td>6-7</td><td>4-5</td><td>2-3</td><td>0-1</td>
	 *		</tr>
	 *		<tr>
	 *			<td>Bit</td>
	 *			<td>7</td><td>6</td><td>5</td><td>4</td><td>3</td><td>2</td><td>1</td><td>0</td>
	 *		</tr>
	 * </table>
	 * @throws RFReaderException If unable to perform command.
	 */
	public void Protect(byte lockReg) throws RFReaderException {
		byte[] cmd = new byte[5];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = 0x19;
		cmd[3] = this.chip_id;
		cmd[4] = lockReg;
		
		sendReceive(cmd, "Unable to protect block.", recv_buf[5]);
	}
	
	/**
	 * Reads which blocks of the selected transponder are locked.
	 *
	 * @return  You can determine which blocks are locked with this
	 * bit-wise coded parameter. Bits to 1 specify which couples of
	 * blocks are locked. <br/>
	 * <table border="1">
	 *		<tr>
	 *			<td>Blocks</td>
	 *			<td>14-15</td><td>12-13</td><td>10-11</td><td>8-9</td><td>6-7</td><td>4-5</td><td>2-3</td><td>0-1</td>
	 *		</tr>
	 *		<tr>
	 *			<td>Bit</td>
	 *			<td>7</td><td>6</td><td>5</td><td>4</td><td>3</td><td>2</td><td>1</td><td>0</td>
	 *		</tr>
	 * </table>
	 * <exception cref="RFReaderException">If unable to perform command.
	 */
	public byte GetProtection() throws RFReaderException {
		byte[] cmd = new byte[3];
		
		cmd[0] = ISO14443B_CUSTOM;
		cmd[1] = ST;
		cmd[2] = 0x18;
		
		sendReceive(cmd, "Unable to get block protection.", recv_buf[5]);
		
		return recv_buf[6];
	}
	
	/**
		* Reads the UID of ST SRIX4K transponders, which is not stored in the data blocks.
		* This command is available only on SRIX4K transponders.
		* @return The UID of a transponder or null if unable to read it.
	 */
		public byte[] GetSRIX4KUid() throws RFReaderException 
		{
			byte[] cmd = new byte[3];

			cmd[0] = ISO14443B_CUSTOM;
			cmd[1] = ST;
			cmd[2] = 0x0B;
			
			try
			{
				send(cmd);
				receive();
			}
			catch (java.io.IOException e)
			{
				//Notify();
				throw new RFReaderException(errMsg("Serial communication problem"));
			}

			if (recv_buf[4] != (byte)0x00)
				return null;

			byte[] uid = new byte[recv_buf[5]];
			ByteUtils.copy(recv_buf, 6, uid, 0, recv_buf[5]);
			
			return uid;
		}
		
		/**
		* Reads the first 4 blocks from the memory of the selected transponder, which
		* contain the unchangeable UID.
		* @return The 8-bytes long UID or null if unable to read it.
		 */
		public byte[] GetSR176Uid()
		{
			try
			{
				return this.Read(0, 4);
			}
			catch (RFReaderException e)
			{
				return null;
			}
		}
}
