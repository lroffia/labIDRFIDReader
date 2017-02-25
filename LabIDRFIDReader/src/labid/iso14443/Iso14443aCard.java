/*
 * Iso14443aCard.java
 *
 * Created on 3 novembre 2004, 8.58
 */

package labid.iso14443;


/** 
* Represents an ISO14443a card
*/
public class Iso14443aCard {
	
	/** 
	* MIFARE Ultralight, with 7 bytes long serial number, no criptography
	* and light data block.
	*/
public static final byte TYPE_MifareUltraLight =  0;
	
	/** 
	* MIFARE 1K, with 4 bytes long serial number, Crypto-1 criptography
	* and 1k of data blocks.
	*/
public static final byte TYPE_Mifare1k = 0x08;
	
	/** 
	* MIFARE 4K, with 4 bytes long serial number, Crypto-1 criptography
	* and 4k of data blocks.
	*/
public static final byte TYPE_Mifare4k = 0x18;
	
	/** 
	* MIFARE DESFire, with 7 bytes long serial number, 3DES criptography
	* and 4k of data blocks.
	*/
public static final byte TYPE_MifareDESFire = 0x20;

/**
 * MIFARE Mini, with 4 bytes long serial number, Crypto-1 criptography
 * and 320 bytes of data blocks.
 */
 public static final byte  TYPE_MifareMini = 0x09;
	
	
	/** Creates a new instance of Iso14443aCard */
	public Iso14443aCard() {
	}
	
	/** 
	* Serial number
	*/
public byte[] uid;
	
	/** 
	* Serial number length
	*/
public int uidLength;
	
	/** 
	* 2 bytes long ATQA code (Acknowledge to Request), which contains information
	* about the tag (see iso14443-3)
	*/
public byte[] ATQA;
	
	/** 
	* SAK code (Select Acknowledge) which contains information
	* about the tag (see iso14443-3)
	*/
public byte SAK;
	
	/** 
	* Creates an instance of Iso14443aCard
	* 
	* @param uidLen Length of Card serial number
	*/
	public Iso14443aCard(int uidLen) {
		this.uid = new byte[uidLen];
		this.uidLength = uidLen;
		this.ATQA = new byte[2];
		this.SAK = 0;
	}
	//CardType Type;
	
	/** 
	* Gets the MIFARE card type of the current Iso14443aCard
	* 
	* @return A known MIFARE card type
	*/
	public String getCardType() {
		String ctype;
		switch (SAK & 0x3C) {
			case TYPE_Mifare1k:
				ctype = "MIFARE 1k";
				break;
			case TYPE_Mifare4k:
				ctype = "MIFARE 4k";
				break;
			case TYPE_MifareMini:
				ctype = "MIFARE Mini";
				break;
			case TYPE_MifareUltraLight:
				ctype = "MIFARE UltraLight";
				break;
			case TYPE_MifareDESFire:
				ctype = "MIFARE DESFire";
				break;
			default:
				ctype = "Unknown";
				break;
		}
		return ctype;
	}
}
