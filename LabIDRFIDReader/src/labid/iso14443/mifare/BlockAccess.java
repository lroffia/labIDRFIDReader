package labid.iso14443.mifare;

/** 
 * Contains the prerequisites for different access types to data blocks.
 */
public class BlockAccess {

	/** 
	 * Prerequisites for accessing a data block in a MIFARE card.
	 */
	public static final int Key_A_or_B = 0;
	public static final int Key_B = 1;
	public static final int Never = 2;
	public int Read;
	public int Write;
	public int Increment;
	public int Decrement;

	/** Creates a new instance of BlockAccess */
	public BlockAccess() {
	}
}
