/*
 * AccessPermission.java
 *
 * Created on 3 novembre 2004, 15.14
 */
package labid.iso14443.mifare;

/** 
 * Represents all access conditions for a sector.
 */
public class AccessPermission {

	public BlockAccess Block0;
	public BlockAccess Block1;
	public BlockAccess Block2;
	public SectorTrailerAccess SectorTrailer;

	/** Creates a new instance of AccessPermission */
	public AccessPermission() {
	}
}
