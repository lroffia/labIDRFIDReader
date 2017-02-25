/*
 * BearsReader.java
 *
 * Created on 13 settembre 2005, 14.19
 */

package labid.reader;

import labid.comm.CableStream;
import labid.comm.SerialStream;
import labid.iso14443.ST_ISO14443B_Reader;
import labid.iso14443.mifare.MifareReader;
import labid.iso15693.ISO15693Reader;

/**
 * This class wraps a {@link labid.iso15693.iso15693.ISO15693Reader }
 * and a {@link labid.iso14443.iso14443.ISO14443Reader } object and cares about
 * automatic serial port connection and notification of incoming
 * transponders events. This class requires firmware version of RFID reader
 * 2.3 or greater.
 */
public class BearsReader implements RFIDTagDetectedListener {
	
	private ISO15693Reader icReader;
	private MifareReader mfReader;
	private ST_ISO14443B_Reader   stReader;
	private boolean connected = false;
	private int eventsNotified = RF_ISOProtocol.None;
	private boolean useBeep = true;
	private RFIDTagDetectedListener evListener;
	
	/**
	 * Creates a new instance of BearsReader. You should call a
	 * {@link #Connect } method before calling any method of unerlying
	 * {@link LabIdReader} objects.
	 */
	public BearsReader() {
	}
	
	/**
	 * Gets the {@link labid.iso15693.iso15693.ISO15693Reader} object contained in BearsReader, in order 
	 * to make ISO15693 commands available to application.
	 * @return A {@link labid.iso15693.iso15693.ISO15693Reader} object.
	 * @throws RFReaderException If the reader had not yet been connected.
	 */
	public ISO15693Reader ISO15693() throws RFReaderException {
		if (connected)
			return icReader;
		else
			throw new RFReaderException("Reader not open.");
	}
	
	/**
	 * Gets the {@link labid.iso14443.readers.iso14443.ST_ISO14443B_Reader} object contained in BearsReader, in order
	 * to make ST ST_ISO14443B commands available to application.
	 * @return A {@link labid.iso14443.readers.iso14443.ST_ISO14443B_Reader} object.
	 * @throws RFReaderException If the reader had not yet been connected.
	 */
	public ST_ISO14443B_Reader ST_ISO14443B() throws RFReaderException {
		if (connected)
			return stReader;
		else
			throw new RFReaderException("Reader not open.");
	}
	
	/**
	 * Gets the {@link labid.iso14443.iso14443.ISO14443Reader} object contained in BearsReader, in order 
	 * to make ISO14443 and Mifare commands available to application.
	 * @return A {@link labid.iso14443.mifare.readers.mifare.MifareReader} object.
	 * @throws RFReaderException If the reader had not yet been connected.
	 */
	public MifareReader Mifare() throws RFReaderException {
		if (connected)
			return mfReader;
		else
			throw new RFReaderException("Reader not open.");
	}
	
	/**
	 * Opens and tests a serial (or USB emulated) port.
	 * @param comPort Number of the COM/serial port
	 * @param baud Baudrate for serial communication
	 * @throws RFReaderException If the connection test failed.
	 * @throws java.io.IOException If unable to open the specified port.
	 */
	public void Connect(String comPort, int baud) throws RFReaderException, java.io.IOException {
		if (!connected) {
			SerialStream testStream;
			/*SerialPortSettings sps = new SerialPortSettings();
			sps.setBaudRate(baud);
			sps.setFlowControl(SerialStream.FLOWCONTROL_NONE);
			sps.setParity(SerialStream.PARITY_NONE);
			sps.setStopBits(SerialStream.STOPBITS_1);
			sps.setTimeout(100);
			sps.setPortNumber(comPort);*/
			
			testStream = new SerialStream();
			testStream.Open(comPort, baud);
			LabIdReader r = new LabIdReader(testStream);
			
			try {
				byte[] version = r.getSoftwareVersion();
				System.out.printf("Reader Version %d.%d Date %d-%d-%d ", version[0],version[1],version[4],version[3],version[2]);
				this.createReaders(testStream);
				return;
			} catch (Exception ex) {
				throw new RFReaderException("Reader not found on COM" + comPort);
			}
		}
	}
	
	
	/**
	 * Opens and tests a serial (or USB emulated) port.
	 * @param comPort Number of the COM/serial port
	 * @throws RFReaderException If the connection test failed.
	 * @throws java.io.IOException If unable to open the specified port.
	 */
	public void Connect(String comPort) throws RFReaderException, java.io.IOException {
		this.Connect(comPort, 115200);
	}
	
	/**
	 * Automatically detects and opens the serial port where the RFID
	 * reader is connected to.
	 * @throws RFReaderException If the connection test failed.
	 * @throws java.io.IOException If unable to find a connection.
	 */
	/*public void Connect() throws RFReaderException, java.io.IOException {
		if (!connected) {
			SerialStream testStream;
			int[] baudrates = { 115200, 9600, 19200, 38400, 57600 };
			
			SerialPortSettings sps = new SerialPortSettings();
			
			sps.setFlowControl(SerialStream.FLOWCONTROL_NONE);
			sps.setParity(SerialStream.PARITY_NONE);
			sps.setStopBits(SerialStream.STOPBITS_1);
			sps.setTimeout(100);
			
			for (int iBaud = 0; iBaud<baudrates.length; iBaud++)
			{
				sps.setBaudRate(baudrates[iBaud]);

				int i;

				if (System.getProperty("os.name").toUpperCase().startsWith("WIN"))
				{
					i = 1;
				}
				else
				{
					i = 0;
				}

				for (; i<40; i++) {
					sps.setPortNumber(i);
					
					try {
						testStream = SerialStream.getInstance(sps);
					} catch (Exception ex) {
						continue;
					}

					LabIdReader r = new LabIdReader(testStream);
					r.setRetry(1);
					try {
						r.getSoftwareVersion();
						this.createReaders(testStream);
						return;
					} catch (Exception ex) {
						try {
							testStream.Close();
						} catch (Exception exc) {}
					}
				}
				
				// wait for rfid reader to reboot after a bad baudrate communication
				try {
					Thread.sleep(10);
				}
				catch (Exception e) {}
						
			}
			throw new RFReaderException();
		}
	}
	*/
	/**
	 * Opens the communication through a CableStream object. This method sends 
	 * automatically a test command to the RFID reader. 
	 * @throws RFReaderException If it fails to find a connection
	 * @param stream Communication stream.
	 */
		public void Connect(CableStream stream) throws RFReaderException, java.io.IOException {
			if (!connected) {
				LabIdReader r = new LabIdReader(stream);
				
				try {
					r.getSoftwareVersion();
					this.createReaders(stream);
					return;
				}
				catch (Exception e) {
					throw new RFReaderException("Reader not found in communication channel");
				}
			}
		}
	
	/**
	 * You can set what kind of transponders you want to be notified
	 * by the BearsReader event dispatcher.
	 * @param ISOProtocol Use {@link RF_ISOProtocol} integer values to specify
	 * protocols. "None" stops event notification.
	 * @throws java.io.IOException If unable to start event notification (usually for
	 * serial communication problems).
	 */
	public void setTagType(int ISOProtocol) throws java.io.IOException {
		this.eventsNotified = ISOProtocol;
		if (connected) {
			if (ISOProtocol == RF_ISOProtocol.None)
				icReader.stopTagEventNotification();
			else {
				icReader.getNextTagEvent(ISOProtocol, this.useBeep);
			}
		}
	}
	
	/**
	 * Gets what kind of transponders are notified to event listeners.
	 * @return An integer value. You can compare it with 
	 * {@link RF_ISOProtocol} values.
	 */
	public int getTagType() {
		return this.eventsNotified;
	}
	
	private void createReaders(CableStream stream) throws java.io.IOException {
		icReader = new ISO15693Reader(stream);
		mfReader = new MifareReader(stream);
		stReader = new ST_ISO14443B_Reader(stream);
		connected = true;
		icReader.addTagEventListener(this); //onRFIDTagDetected += new RFIDTagEventHandler(icReader_onRFIDTagDetected);
		this.setTagType(this.eventsNotified);
	}
	
	/**
	 * Registers an object as listener for incoming transponder event.
	 * Only one event handler is notified.
	 * @param listener The listener object.
	 */
	public void addTagEventListener(RFIDTagDetectedListener listener) {
		this.evListener = listener; //stupid implementation: only one event handler is notified
	}
	
	/**
	 * You should not use this method (it is a handler for low
	 * level events).
	 * @param args --
	 */
	public void TagDetected(int args) throws java.io.IOException {
		if (this.evListener != null) {
			try {
				//eseguo il delegato e riprendo la notifica eventi
				this.evListener.TagDetected(args);
			} catch (Exception ex){} // LabIdReader dovrebbe intercettare l'eccezione?
		}
		
		icReader.getNextTagEvent(this.eventsNotified, this.useBeep);
	}
	
	/**
	 * Stops event notifications and closes connection. You should always
	 * call this method when exiting from your application, otherwise the
	 * RFID reader remains in search of the next transponder.
	 * @throws java.io.IOException If there was a serial communication problem.
	 */
	public void dispose() throws java.io.IOException {
		//fermo il thread di notifica dei tag
		if (icReader != null) {
			icReader.stopTagEventNotification();
			icReader.close();
		}
	}
	
	/**
	 * Specifies if the RFID reader must produce a short sound
	 * each time a transponder is detected.
	 * @param useIt Option value.
	 */
	public void setBeep(boolean useIt) {
		this.useBeep = useIt;
	}
	
	/**
	 * Tells if the RFID reader must produce a short sound
	 * each time a transponder is detected.
	 * @return Option value.
	 */
	public boolean getBeep() {
		return this.useBeep;
	}
	
	/** 
	 * Tests the current connection.
	 * @return true if the connection is working
	 */
	public boolean testConnection() {
		if (!this.connected)
			return false;
		else
		{
			try
			{
				this.mfReader.getSoftwareVersion();
				return true;
			}
			catch (Exception e) {
				this.connected = false;
				return false;
			}
		}
	}
}
