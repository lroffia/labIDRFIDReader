/*
 * RF_ISOProtocol.java
 *
 * Created on 13 settembre 2005, 15.22
 *
 * To change this template, choose Tools | Options and locate the template under
 * the Source Creation and Management node. Right-click the template and choose
 * Open. You can then make changes to the template in the Source Editor.
 */

package labid.reader;

/**
 *
 * @author Daniele
 */
public class RF_ISOProtocol {
	
	/** Creates a new instance of RF_ISOProtocol */
	private RF_ISOProtocol() {}
	
	public static final int None      = 0x00;
	public static final int Any       = 0x0F;
	public static final int ISO15693  = 0x01;
	public static final int ISO14443A = 0x02;
	public static final int ISO14443B = 0x04;
	public static final int EPC       = 0x08;
}
