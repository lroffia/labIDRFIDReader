package labid.comm;

import jssc.*;

import java.io.*;

public class SerialStream implements CableStream {
	
	private SerialPort sp;
	
	public static final int PARITY_NONE = SerialPort.PARITY_NONE;
	public static final int PARITY_EVEN = SerialPort.PARITY_EVEN;
	public static final int PARITY_ODD  = SerialPort.PARITY_ODD;
	
	public static final int FLOWCONTROL_NONE  = SerialPort.FLOWCONTROL_NONE;
	public static final int FLOWCONTROL_HARDWARE = SerialPort.FLOWCONTROL_RTSCTS_IN;
	public static final int FLOWCONTROL_SOFTWARE = SerialPort.FLOWCONTROL_XONXOFF_IN;
	
	public static final int STOPBITS_1 = SerialPort.STOPBITS_1;
	public static final int STOPBITS_1_5 = SerialPort.STOPBITS_1_5;
	public static final int STOPBITS_2 = SerialPort.STOPBITS_2;
	
	public static final int DATABITS_8 = SerialPort.DATABITS_8;
	public static final int DATABITS_7 = SerialPort.DATABITS_7;
	
	public SerialStream()  {}
	
	public void Open(String port, int baudrate) throws IOException {
		
		try {
			sp = new SerialPort(port);
			sp.openPort();
			sp.setParams(baudrate, 
					DATABITS_8,
					STOPBITS_1,
					PARITY_NONE);
			sp.setFlowControlMode(FLOWCONTROL_NONE);
		}
		catch(Exception e) {throw new IOException();}
	}
	
	public  void Close() throws IOException {
		try 
		{
			sp.closePort();
		} 
		catch (SerialPortException e) {throw new IOException(e.getMessage());}
	}
	
	public int Read(byte[] buffer, int offset, int count) throws IOException{
		try 
		{
			byte[] temp = sp.readBytes(count);
			if (temp.length == count) {
				for (int i = 0; i < count ; i++) buffer[offset+i] = temp[i];
			}
			return temp.length;
		} 
		catch (SerialPortException e) {throw new IOException (e.getMessage());}
	}
	
	public  void Write(byte[] buffer, int offset, int count) throws IOException {
		byte[] temp = new byte[count-offset];
		for (int i = offset; i < count ; i++) temp[i-offset] = buffer[i];
		try 
		{
			sp.writeBytes(temp);
		} 
		catch (SerialPortException e) {throw new IOException(e.getMessage());}
	}
	
	public int Read(byte[] buffer) throws IOException {
		try 
		{
			buffer = sp.readBytes();
		} 
		catch (SerialPortException e) {throw new IOException(e.getMessage());}
		
		return buffer.length;
	}
	
	public void Write(byte[] buffer) throws IOException {
		try 
		{
			sp.writeBytes(buffer);
		} 
		catch (SerialPortException e) {throw new IOException(e.getMessage());}
	}
	
	public void SetPortSettings(int baudrate, int flowcontrol, int parity, int databits, int stopbits) throws Exception {
		sp.setParams(baudrate, databits, stopbits, parity);
		sp.setFlowControlMode(flowcontrol);
	}
	
	/*
	public static SerialStream getInstance(SerialPortSettings sps) throws IOException
	{
		SerialStream sp;

		String osName = System.getProperty("os.name").toUpperCase();
		
		// windows
		if (osName.startsWith("WINDOWS"))
		{
			try {
				sp = new SerialStream("COM" + sps.getPortNumber());
				sp.SetPortSettings((int)sps.getBaudRate(), sps.getFlowControl(), sps.getParity(), (byte)8, sps.getStopBits());
			}
			catch (Exception e) {
				throw new IOException("Unable to open COM" + sps.getPortNumber());
			}
			return sp;
		}
		
		// MAC OS X
		if (osName.startsWith("MAC OS X"))
		{
			try
			{
				//e.g. tty.usbserial-000013FA
				sp = new SerialStream(sps.getPortName());
			}
			catch (Exception ex)
			{
				sp = null;
			}
			return sp;
		}	
		
		// Linux
		if (osName.startsWith("LINUX"))
		{
			// try to open USB emulated serial port
			try
			{
				sp = new SerialStream("/dev/ttyUSB" + sps.getPortNumber());
			}
			catch (Exception ex)
			{
				sp = null;
			}

			// try to open hardware serial port
			if (sp == null)
			{
				try
				{
					sp = new SerialStream("/dev/ttyS" + sps.getPortNumber());
				}
				catch (Exception ex)
				{
					sp = null;
				}
			}
			return sp;
		}
		
		throw new IOException("OS not supported " + osName);
	}*/
}
