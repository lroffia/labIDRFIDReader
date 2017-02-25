
package labid.iso15693.icode;

/**
 * Specifies what passwords are required to get access to a protected page.
 * If 64-bit protection is enabled, both Read and Write password are always required.
 */
public enum ProtectionStatus {

	/**
	 * Public, no password required
	 */
	Public(0x00),
	/**
	 * Read and Write protected by Read password
	 */
	RW_ProtectedByReadPwd(0x01),
	/**
	 * Write protected by Write password
	 */
	W_ProtectedByWritePwd(0x10),
	/**
	 * Read protected by Read password and Write protected by Write password
	 */
	RW_ProtectedByReadAndWritePwd(0x11);
	private final int p;

	ProtectionStatus(int ps) {
		this.p = ps;
	}

	public byte byteValue() {
		return (byte) (p & 0xFF);
	}
}
