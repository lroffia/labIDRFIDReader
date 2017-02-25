package labid.iso14443.mifare;

import labid.comm.ByteUtils;
import labid.reader.LabIdReader;
import labid.reader.RFReaderException;

/** 
* Descrizione di riepilogo per MifareLowLevelReader.
*/
public class MifareLowLevelReader extends LabIdReader {
	public MifareLowLevelReader() {
		super();
	}
	
	private byte[] shortRequest(byte req) throws RFReaderException {
		Wait();
		
		byte[] cmd = new byte[2];
		cmd[0] = (byte)0xA0;
		cmd[1] = req;
		
		try {
			send(cmd);
			receive();
		}
		catch (Exception e) {
			throw new RFReaderException("Serial communication problem");
		}
		
		if (recv_buf[4] != 0) {
			Notify();
			throw new RFReaderException();
		}
		
		int resLen = recv_buf[0] - 2 - 5; //CRC, header
		byte[] result = new byte[resLen];
		ByteUtils.copy(recv_buf, 5, result, 0, resLen);
		
		Notify();
		return result;
	}
	
	/** 
	///
	* 

*/
public byte[] REQA() throws RFReaderException {
		return shortRequest((byte)0x26);
	}
	
	public byte[] WUPA() throws RFReaderException {
		return shortRequest((byte)0x52);
	}
	
	public byte[] HLTA() throws RFReaderException {
		return shortRequest((byte)0x50);
	}
	
	public byte[] ANTICOLLISION_1() throws RFReaderException {
		return CascAnticoll() ;
	}
	
	public byte[] SELECT_1(byte[] uid) throws RFReaderException {
		if (uid.length != 4)
			throw new RFReaderException("UID must be 4 bytes long");
		
		Wait();
		
		byte[] cmd = new byte[7];
		cmd[0] = (byte)0xa0;
		cmd[1] = (byte)0x93;
		cmd[2] = 0x70;
		ByteUtils.copy(uid, 0, cmd, 3, 4);
		
		try {
			send(cmd);
			receive();
		}
		catch (Exception e) {
			Notify();
			throw new RFReaderException("Serial communication problem");
		}
		
		Notify();
		return recv_buf;
	}

	private byte[] CascAnticoll() throws RFReaderException {
		Wait();
		
		byte[] cmd = new byte[3];
		cmd[0] = (byte)0xa0;
		cmd[1] = (byte)0x93;
		cmd[2] = 0x00;
		
		try {
			send(cmd);
			receive();
		}
		catch (Exception e) {
			Notify();
			throw new RFReaderException("Serial communication problem");
		}
		
		int resplen;
		if (recv_buf[4] == 0x00)
			resplen = 5;
		else resplen = 1;
		
		byte[] result = new byte[resplen];
		ByteUtils.copy(recv_buf,4,result, 0, resplen);
		
		Notify();
		return result;
	}
}