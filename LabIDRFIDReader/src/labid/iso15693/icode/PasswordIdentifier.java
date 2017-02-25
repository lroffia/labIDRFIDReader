package labid.iso15693.icode;

/**
 * Specifies the type of protection provided by a password
 * @author Daniele
 */
public enum PasswordIdentifier {

	Read(0x01),
	Write(0x02),
	Privacy(0x04),
	Destroy(0x08),
	EAS(0x10);
	private final int p;

	PasswordIdentifier(int pi) {
		this.p = pi;
	}

	public byte byteValue() {
		return (byte) (p & 0xFF);
	}
}
