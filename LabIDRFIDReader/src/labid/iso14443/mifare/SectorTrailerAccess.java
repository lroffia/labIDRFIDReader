package labid.iso14443.mifare;

/** 
 * Contains the prerequisites for different access types to sector trailers.
 */
public class SectorTrailerAccess {

	/** 
	 * Prerequisites for accessing a sector trailer in a MIFARE card.
	 */
	public static final int Key_A_or_B = 0;
	public static final int Key_B = 1;
	public static final int Key_A = 2;
	public static final int Never = 3;
	public int WriteKey_A;
	public int WriteAccessBits;
	public int ReadAccessBits;
	public int ReadKey_B;
	public int WriteKey_B;

	/** Creates a new instance of SectorTrailerAccess */
	public SectorTrailerAccess() {
	}
}
