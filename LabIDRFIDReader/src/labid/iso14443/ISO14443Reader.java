package labid.iso14443;

import java.io.IOException;

import labid.comm.ByteUtils;
import labid.comm.CableStream;
import labid.reader.LabIdReader;
import labid.reader.RFReaderException;


/**
 * This class provides a software interface for ISO15693 commands
 * using LAB ID multi-standard tag reader. If you want to have a technical
 * background of used technologies and standards, please refer to ISO14443.
 * If you need to use ISO15693 commands, use class <see cref="iso15693.ISO15693Reader"/>.
 */
public class ISO14443Reader extends LabIdReader {
	
	/**
	 * Instantiates a new ISO15693Reader object
	 */
	public ISO14443Reader() {
		super();
	}
	
	/**
	 * Instantiates a new LabIdReader object connected through a SerialStream object
	 *
	 * @param stream Communication stream.
	 */
	public ISO14443Reader(CableStream stream) {
		super(stream);
	}
	
	/**
	 * Puts one Iso14443a tag in the Active state if it was in the Idle state.
	 *
	 * @return An object containig information about the activated transponder or null if 
	 * there was no tag to activate.
	 * @throws RFReaderException If unable to perform operation.
	 * With message.
	 */
	public Iso14443aCard ActivateIdleA() throws RFReaderException {
			/* Formato della risposta:
			 * 0 - 4 header del protocollo
			 * 5 - .. uid (lungh. variabile)
			 * ATQA LSB
			 * ATQA MSB
			 * SAK
			 * CRC LSB
			 * CRC MSB
			 */
		
		//Wait();
		byte[] cmd = new byte[2];
		cmd[0] = (byte)0xA0;
		cmd[1] = (byte)0x90;
		
		try
		{
			send(cmd);
			receive();
		}
		catch (Exception e)
		{
			throw new RFReaderException("Serial communication problem.");
		}
		
		if (recv_buf[4] != (byte)0)
		{
			//Notify();
			return null;
		}
		
		int msgLen = recv_buf[0] & 0xFF;
		int uidLen = msgLen - 10;
		byte ATQA1; //LSB di ATQA. I 2 bit + sign. contengono il tipo di uid
		ATQA1 = recv_buf[msgLen - 5]; // atqa1 - atqa2 - sak - crcL - crcM
		
		Iso14443aCard card = new Iso14443aCard(uidLen);
		ByteUtils.copy(recv_buf,5,card.uid,0,uidLen);
		
		card.ATQA[0] = ATQA1;
		card.ATQA[1] = recv_buf[msgLen - 4];
		card.SAK = recv_buf[msgLen - 3];
		
		//Notify();
		return card;
	}
	
	/**
	 * Puts one Iso14443a tag in the Active state if it was in the Halt state.
	 *
	 * @param uid Serial number of the transponder to activate.
	 * @return Information about the activated transponder or null if there was no tag to wake up.
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public Iso14443aCard ActivateWakeupA(byte[] uid) throws RFReaderException {
			/* Formato della risposta:
			 * 0 - 4 header del protocollo
			 * 5 - .. uid (lungh. variabile)
			 * ATQA LSB
			 * ATQA MSB
			 * SAK
			 * CRC LSB
			 * CRC MSB
			 */
		
		//Wait();
		byte[] cmd = new byte[2 + uid.length];
		cmd[0] = (byte)0xA0;
		cmd[1] = (byte)0x91;
		ByteUtils.copy(uid, 0, cmd, 2, uid.length);
		
		try
		{
			send(cmd);
			receive();
		}
		catch (Exception e)
		{
			throw new RFReaderException("Serial communication problem.");
		}
		
		if (recv_buf[4] != (byte)0)
		{
			//Notify();
			return null;
		}
		
		int msgLen = recv_buf[0] & 0xFF;
		int uidLen = 4;
		byte ATQA1; //LSB di ATQA. I 2 bit + sign. contengono il tipo di uid
		ATQA1 = recv_buf[msgLen - 5]; // atqa1 - atqa2 - sak - crcL - crcM
		switch (ATQA1 >> 6) //vedi pag 15,19 di iso14443-3
		{
			case 0x00:
				uidLen = 4; //single size
				break;
			case 0x01:
				uidLen = 7; //double size
				break;
			case 0x02:
				uidLen = 10; //triple size
				break;
		}
		
		
		byte[] result = new byte[uidLen];
		ByteUtils.copy(recv_buf,5,result,0,uidLen);
		
		Iso14443aCard card = new Iso14443aCard(uidLen);
		ByteUtils.copy(recv_buf,5,card.uid,0,uidLen);
		
		card.ATQA[0] = ATQA1;
		card.ATQA[1] = recv_buf[msgLen - 4];
		card.SAK = recv_buf[msgLen - 3];
		
		//Notify();
		return card;
		
	}
	
	/**
	 * Passes a 6 bytes long key to the reader for authenticating a card
	 *
	 * @param key
	 */
	protected void LoadKey(byte[] key) throws RFReaderException {
		if (key.length != 6)
			throw new RFReaderException(errMsg("Keys must be 6 bytes long"));
		
		//Wait();
		byte[] cmd = new byte[8];
		cmd[0] = (byte)0xA0;
		cmd[1] = 0x19;
		ByteUtils.copy(key, 0, cmd, 2, 6);
		
		sendReceive(cmd, "Could not load key");
		
		//Notify();
		return ;
	}
	
	/**
	 * Loads a key stored in internal reader's EEPROM for authenticating to a card.
	 * @param keyIndex Index of the key between 0 and 31 included.
	 */
	protected void LoadKey(int keyIndex) throws RFReaderException
	{	
		if (keyIndex > 31) 
			throw new RFReaderException(errMsg("Key index must be between 0 and 31."));

		//Wait();
		byte[] cmd = new byte[3];
		cmd[0] = (byte)0xA0;
		cmd[1] = (byte)0x0B;
		cmd[2] = (byte)keyIndex;

		sendReceive(cmd,"Could not load key.");

		//Notify();
		return ;
	}
	
	
	protected void mf_Authentication(byte AorB, byte[] uid, int blockAddress) throws RFReaderException {
		//Wait();
		int uidlen = uid.length;
		byte[] cmd = new byte[3 + uidlen];
		cmd[0] = (byte)0xA0;				//control byte: iso14443
		cmd[1] = AorB;						//command code (authA(0x60) o authB(0x61))
		cmd[2] = (byte) blockAddress;		//blocco da autenticare
		ByteUtils.copy(uid, 0, cmd, 3, uidlen);	//uid della card
		
		sendReceive(cmd, "Could not authenticate");
		
		//Notify();
		return ;
	}
	
	/**
	 * Authenticates for access to a data block of a MIFARE card with Key A.
	 * All accesses to data blocks need authentication except for MIFARE Ultralight cards.
	 *
	 * @param uid Serial number of the addresses tag
	 * @param key 6 bytes long key A
	 * @param blockAddress Index of the block to access
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void AuthenticateA(byte[] uid, byte[] key, int blockAddress) throws RFReaderException {
		LoadKey(key);
		mf_Authentication((byte)0x60, uid, blockAddress);
	}
	
	/**
	 * Authenticates for access to a data block of a MIFARE card with Key B.
	 * All accesses to data blocks need authentication except for MIFARE Ultralight cards.
	 *
	 * @param uid Serial number of the addresses tag
	 * @param key 6 bytes long key A
	 * @param blockAddress Index of the block to access
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void AuthenticateB(byte[] uid, byte[] key, int blockAddress) throws RFReaderException {
		LoadKey(key);
		mf_Authentication((byte)0x61, uid, blockAddress);
	}
	
	/**
	 * Reads 16 bytes of a block from the activated card.
	 *
	 * @param blockAddress Index of the data block to read.
	 * @return The content of the data block.
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public byte[] Read16(int blockAddress) throws RFReaderException {
		//Wait();
		
		byte[] cmd = new byte[3];
		cmd[0] = (byte)0xA0;			// control byte: iso14443
		cmd[1] = 0x30;					// command code: read16
		cmd[2] = (byte) (blockAddress & 0xFF);	// numero del blocco da leggere
		
		sendReceive(cmd, "Could not read sector");
		
		byte[] result = new byte[16]; //i Mifare hanno blocchi di 16 byte
		ByteUtils.copy(recv_buf, 5, result, 0, 16);
		
		//Notify();
		return result;
	}
	
	/**
	 * Writes 16 bytes to a data block of the activated card. Be careful
	 * with the data format when writing to sector trailers on MIFARE cards.
	 *
	 * @param data 16 bytes long data array.
	 * @param blockAddress Index of the block to write.
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void Write16(byte[] data, int blockAddress) throws RFReaderException {
		if (data.length != 16)
			throw new RFReaderException(errMsg("Data must be 16 bytes long"));
		
		//Wait();
		
		byte[] cmd = new byte[19];
		cmd[0] = (byte)0xA0;			//control byte iso14443
		cmd[1] = (byte)0xA0;			//command code: write16
		cmd[2] = (byte)(blockAddress & 0xFF);	//indirizzo del blocco da scrivere
		ByteUtils.copy(data, 0, cmd, 3, data.length);
		
		sendReceive(cmd, "Could not write sector");
		
		//Notify();
	}
	
	/**
	 * Writes 4 bytes to a data block of a previously activated
	 * MIFARE Ultralight card.
	 *
	 * @param data 4 bytes to write on data block.
	 *
	 */
	public void Write4(byte[] data, int blockAddress) throws RFReaderException {
		if (data.length != 4)
			throw new RFReaderException(errMsg("Data must be 4 bytes long"));
		
		//Wait();
		
		byte[] cmd = new byte[7];
		cmd[0] = (byte)0xA0;			//control byte iso14443
		cmd[1] = (byte)0xA2;			//command code: write16
		cmd[2] = (byte)(blockAddress & 0xFF);	//indirizzo del blocco da scrivere
		ByteUtils.copy(data, 0, cmd, 3, data.length);
		
		sendReceive(cmd, "Could not write sector");
		
		//Notify();
	}
	
	protected void mf_IncDec(byte incDec, int amount, int blockAddress, boolean automaticTransfer) throws RFReaderException {
		//Wait();
		
		byte[] cmd = new byte[8];
		cmd[0] = (byte)0xA0;	//control byte: iso14443
		cmd[1] = incDec;		//command code: increment(0xc1) or decrement(0xc0)
		if (automaticTransfer)
			cmd[2] = 0x00;
		else
			cmd[2] = 0x01;
		cmd[3] = (byte) blockAddress;
		
		cmd[4] = (byte) (amount & 0xFF);
		cmd[5] = (byte) ((amount >>  8)& 0xFF);
		cmd[6] = (byte) ((amount >> 16)& 0xFF);
		cmd[7] = (byte) ((amount >> 24)& 0xFF);
		
		sendReceive(cmd, "Could not change value");
		
		//Notify();
	}
	
	/**
	 * Increments by the specified amount the value stored in a data block
	 * of a previously activated MIFARE card. The data block must have the
	 * MIFARE value format in order to perform this command.
	 *
	 * @param amount Signed integer quantity to add to the current value
	 * stored in the data block.
	 * @param blockAddress Index of the data block.
	 * @param automaticTransfer Specifies if using automatic transfer. If
	 * you don't use it, you must execute a <see cref="mf_Transfer"/> command
	 * in order to confirm your Increment operation. If you don't execute Transfer
	 * the previous value will be restored when card is powered off, deselected or
	 * targeted by another command.
	 *
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void Increment(int amount, int blockAddress, boolean automaticTransfer) throws RFReaderException {
		mf_IncDec((byte)0xC1, amount, blockAddress, automaticTransfer);
	}
	
	/**
	 * Decrements by the specified amount the value stored in a data block
	 * of a previously activated MIFARE card. The data block must have the
	 * MIFARE value format in order to perform this command.
	 *
	 * @param amount Signed integer quantity to subtract from the current
	 * value stored in the data block.
	 * @param blockAddress Index of the data block.
	 * @param automaticTransfer Specifies if using automatic transfer. If
	 * you don't use it, you must execute a <see cref="mf_Transfer"/> command
	 * in order to confirm your Increment operation. If you don't execute Transfer
	 * the previous value will be restored when card is powered off, deselected or
	 * targeted by another command.
	 *
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void Decrement(int amount, int blockAddress, boolean automaticTransfer) throws RFReaderException {
		mf_IncDec((byte)0xC0, amount, blockAddress, automaticTransfer);
	}
	
	/**
	 * Confirms the previous Increment/Decrement operation performed without
	 * automatic transfer.
	 *
	 * @param blockAddress Index of the data block
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void Transfer(int blockAddress) throws RFReaderException {
		byte[] cmd = new byte[3];
		cmd[0] = (byte)0xA0;				//control byte: iso14443
		cmd[1] = (byte)0xB0;				//command code: transfer
		cmd[2] = (byte)(blockAddress & 0xFF);
		
		sendReceive(cmd, "Could not perform Transfer");
		
		//Notify();
	}
	
	
	/**
	 * Puts the selected Iso14443a tag in the Halt state.
	 *
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public void HaltA() throws RFReaderException {
		byte[] cmd = new byte[2];
		cmd[0] = (byte)0xA0;	//control byte: iso14443
		cmd[1] = (byte)0x50;	//command code: HALTa
		
		sendReceive(cmd, "Could not halt tag");
		
		//Notify();
	}
	
	/**
	 * Retrieves serial numbers of all Iso14443a cards in RF field.
	 *
	 * @return An array of serial numbers. <b>They may have variable length.</b> 
	 * or null if no cards were found.
	 * @throws RFReaderException If unable to perform operation.
	 *
	 */
	public byte[][] ShowCards() throws RFReaderException {
		byte[] cmd = new byte[2];
		cmd[0] = (byte)0xA0;		//control byte: iso14443
		cmd[1] = (byte)0xD0;		//command code: show cards
		
		try {
			send(cmd);
			receive();
		}
		catch (java.io.IOException e) {
			//Notify();
			throw new RFReaderException(errMsg("Serial communication problem"));
		}
		
		if (recv_buf[4] != 0) {
			//Notify();
			return null;
		}
		
			/* Il reader risponde con:
			 * header del protocollo (comune agli altri comandi): 5 bytes
			 * n. di tag rilevati
			 *		---- x n. di tag rilevati
			 *		| lunghezza dell'uid
			 *		| uid
			 *		----
			 */
		int nTag = recv_buf[5] & 0xFF;
		byte[][] result = new byte[nTag][];
		int index = 6; //
		int uidLen;
		for (int i=0; i<nTag; i++) {
			uidLen = recv_buf[index] & 0xFF;
			index++; //muovo il puntatore all'inizio dell'uid
			result[i] = new byte[uidLen];
			ByteUtils.copy(recv_buf, index, result[i], 0, uidLen);
			index += uidLen;
		}
		//Notify();
		return result;
	}
	
	/**
	* Writes a 6 bytes long key to reader's internal EEPROM. Keys are write-only,
	* i.e. it is impossible to read them, even by the reader itself.
	* Keys are addressed by an index between 0 and 31 included, which allows to load
	* them later.
	* @param keyIndex Index of the key.
	* @param key Key value. If it is longer than 6 bytes, it will be truncated.
	 */
	public void StoreKeyInEEPROM(int keyIndex, byte[] key) throws RFReaderException
	{
		if (keyIndex > 31)
			throw new RFReaderException(errMsg("Key index must be between 0 and 31."));

		if (key.length < 6)
			throw new RFReaderException(errMsg("Key must be 6 bytes long."));

		//Wait();
		byte[] cmd = new byte[9];
		cmd[0] = (byte)0xA0;
		cmd[1] = (byte)0x0C;
		cmd[2] = (byte)keyIndex;
		ByteUtils.copy(key, 0, cmd, 3, 6);

		sendReceive(cmd, "Could not write key to reader's EEPROM");

		//Notify();
		return;
	}
	
	
	/**
	* Authenticates for access to a data sector of a MIFARE card with Key A. The key
	* is stored in internal Reader's EEPROM and is referenced by an index between 0
	* and 31 included. <br/>
	* All accesses to data blocks need authentication except for MIFARE Ultralight cards.
	* @param uid Serial number of the addresses tag
	* @param keyIndex Address of a key stored in reader's internal EEPROM
	* @param blockAddress Index of the block to access 
	* @throws RFReaderException If unable to perform operation. With message. 
	 */
	public void AuthenticateA(byte[] uid, int keyIndex, int blockAddress) throws RFReaderException
	{
		LoadKey(keyIndex);
		mf_Authentication((byte)0x60, uid, blockAddress);
	}

	
	/**
	* Authenticates for access to a data sector of a MIFARE card with Key B. The key
	* is stored in internal Reader's EEPROM and is referenced by an index between 0
	* and 31 included. <br/>
	* All accesses to data blocks need authentication except for MIFARE Ultralight cards.
	* @param uid Serial number of the addresses tag
	* @param keyIndex Address of a key stored in reader's internal EEPROM
	* @param blockAddress Index of the block to access 
	* @throws RFReaderException If unable to perform operation. With message. 
	 */
	public void AuthenticateB(byte[] uid, int keyIndex, int blockAddress) throws RFReaderException 
	{
		LoadKey(keyIndex);
		mf_Authentication((byte)0x61, uid, blockAddress);
	}

	public boolean REQ_A() throws RFReaderException
		{
			byte[] cmd = new byte[2];
			cmd[0] = (byte)0xA0; //iso14443
			cmd[1] = (byte)0x26; //REQ-A

			try
			{
				send(cmd);
				receive();
			}
			catch (IOException ioe)
			{
				//Notify();
				throw new RFReaderException(errMsg("Serial communication problem"));
			}

			return (recv_buf[4] == 0) ;
		}

		/// <summary>
		/// Sends a REQ-B request to ISO14443B compliant tags.
		/// </summary>
		/// <param name="afi">AFI of the tag. 0 means "all tags".</param>
		/// <returns>ATQB response if a tag has been found. null otherwise.<br/>
		/// ATQB is composed by: { 0x50, PUPI (4 bytes), Application data (4 bytes), Protocol Info (3 bytes) }
		/// </returns>
		public byte[] REQ_B(int afi) throws RFReaderException
		{
			byte[] cmd = new byte[3];
			cmd[0] = (byte)0xC0; // iso14443B
			cmd[1] = (byte)0x05; // REQ-B
			cmd[2] = (byte)afi; // AFI

			try
			{
				send(cmd);
				receive();

				if (recv_buf[4] == 0)
				{
					int atqbLen = recv_buf[0]-5;
					byte[] atqb = new byte[atqbLen];
					ByteUtils.copy(recv_buf, 5, atqb, 0, atqbLen);
					return atqb;
				}
				else
				{
					return null;
				}
			}
			catch (IOException ex)
			{
				//Notify();
				throw new RFReaderException(errMsg("Serial communication problem"));
			}
		}

		public byte[] ISO14443A_3_ExchangeBytes(byte[] send) throws RFReaderException
		{
			int datalen = 0;

			byte[] cmd = new byte[datalen + 3]; // i dati da inviare + 3 byte di header

			cmd[0] = (byte)0xA0;
			cmd[1] = (byte)0xD1; //command code Exchange ISO14443-3
			cmd[2] = (byte)datalen;

			ByteUtils.copy(send, 0, cmd, 3, datalen);

			sendReceive(cmd, "Unable to transceive");

			int resplen = recv_buf[5];

			byte[] result = new byte[resplen];
			ByteUtils.copy(recv_buf, 6, result, 0, resplen);

			return result;
		}

		public byte[] ISO14443A_4_ExchangeBytes(byte[] send) throws RFReaderException
		{
			int datalen = 0;

			byte[] cmd = new byte[datalen + 3]; // i dati da inviare + 3 byte di header

			cmd[0] = (byte)0xA0;
			cmd[1] = (byte)0xD2; //command code Exchange ISO14443-4
			cmd[2] = (byte)datalen;

			ByteUtils.copy(send, 0, cmd, 3, datalen);

			sendReceive(cmd, "Unable to transceive");

			int resplen = recv_buf[5];

			byte[] result = new byte[resplen];
			ByteUtils.copy(recv_buf, 6, result, 0, resplen);

			return result;
		}

		/// <summary>
		/// Executes the RATS (Request Answer to Select) ISO14443A/4 command, which enables
		/// the fourth level of the communication protocol. Returns the ATS response from the tag.
		/// </summary>
		/// <returns></returns>
		public byte[] RATS() throws RFReaderException
		{
			byte[] cmd = new byte[2];

			cmd[0] = (byte)0xA0;
			cmd[1] = (byte)0xE0; //command code RATS

			sendReceive(cmd, "Unable to execute RATS");

			int resplen = recv_buf[5];

			byte[] result = new byte[resplen];
			ByteUtils.copy(recv_buf, 5, result, 0, resplen);

			return result;
		}
}