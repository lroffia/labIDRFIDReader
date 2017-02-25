/*----------------------------------------------
 * Progetto/package: labid.iso14443
 * Programmatore   : Daniele
 * File            : PicopassReader.java
 * Data            : 15-feb-2011
 *
 * (c) LAB ID Srl
 *----------------------------------------------
 */
/*
 * To change this template, choose Tools | Templates
 * and open the template in the editor.
 */
package labid.picopass;

import labid.comm.ByteUtils;
import labid.comm.CableStream;
import labid.reader.LabIdReader;
import labid.reader.RFReaderException;

/**
 * PicopassReader provides methods for handling of Inside Contactless Picopass tags.
 * These tags work both with ISO14443B and ISO15693, but only the ISO14443B standard
 * is used in this class.
 * @author Daniele Zanoli
 */
public class PicopassReader extends LabIdReader
{

	/** Creates a new instance of PicopassReader */
	public PicopassReader()
	{
		super();
	}

	/** Instantiates a new object connected through a SerialStream object
	 *
	 * @param stream Communication stream.
	 */
	public PicopassReader(CableStream stream)
	{
		super(stream);
	}

	/**
	 * Selects a Picopass tag and reads its UID
	 * @return The UID of the selected tag or null if no tag has been found
	 * @throws RFReaderException
	 */
	public byte[] GetUID() throws RFReaderException
	{
		byte[] result = null;
		byte[] cmd = new byte[2];

		cmd[0] = (byte) 0xC2; // picopass protocol
		cmd[1] = (byte) 0x81; // Select + GetUID

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

		// se status = OK
		if (recv_buf[4] == (byte) 0x00)
		{
			// copia l'uid nel risultato
			int uidlen = recv_buf[5] & 0xFF;
			result = new byte[uidlen];
			ByteUtils.copy(recv_buf, 6, result, 0, uidlen);
		}

		return result;
	}
}
