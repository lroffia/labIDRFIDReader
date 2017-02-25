package labid.iso14443.mifare;

import labid.reader.RFReaderException;

/** 
* Exception for Mifare events.
*/
public class MifareException extends RFReaderException {
	/**
	 * 
	 */
	private static final long serialVersionUID = 7919906697650860513L;

	/**  Creates a new instance of <code>MifareException</code> without detail message.
	*/
public MifareException() {
	}
	
	/**  Constructs an instance of <code>RFReaderException</code> with the specified detail message.
	* 
	* @param msg the detail message.
	*/
public MifareException(String msg) {
		super(msg);
	}
}
