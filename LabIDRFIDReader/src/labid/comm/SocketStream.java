/*
 * SocketStream.java
 *
 * Created on 18 febbraio 2005, 10.03
 */

package labid.comm;

import java.net.*;
import java.io.*;

/**
 *
 * @author  Daniele
 */
	/// <summary>
	/// Represents a stream through TCP/IP Socket compatible with SerialStream
	/// </summary>
	public class SocketStream implements CableStream
	{
		private Socket socket;
		private InputStream in;
		private OutputStream out;

		/// <summary>
		/// Opens a TCP/IP stream.
		/// </summary>
		/// <param name="ipAddress">IP address of the server, in dotted notation. </param>
		/// <param name="port">TCP port</param>
		public SocketStream(String ipAddress, int port) throws IOException, UnknownHostException
		{
			socket = new Socket(ipAddress, port);
			this.in = socket.getInputStream();
			this.out = socket.getOutputStream();
		}

		/// <summary>
		/// Closes the socket.
		/// </summary>
		public void Close() throws IOException
		{
			socket.shutdownInput();
			socket.shutdownOutput();
			socket.close();
		}

		/// <summary>
		/// Tries to read some bytes from the stream and puts them into a buffer.
		/// </summary>
		/// <param name="buffer">The destination buffer.</param>
		/// <param name="offset">Initial offset of the buffer.</param>
		/// <param name="length">Maximum number of bytes to read.</param>
		/// <returns>Number of read bytes.</returns>
		public int Read(byte[] buffer, int offset, int length) throws IOException
		{
			return in.read(buffer, offset, length);
		}

		/// <summary>
		/// Reads all bytes from the stream until timeout expires.
		/// </summary>
		/// <param name="buffer">The destination buffer.</param>
		/// <returns>Number of read bytes.</returns>
		public  int Read(byte[] buffer) throws IOException
		{
			return in.read(buffer);
		}

		/// <summary>
		/// Writes some bytes to the socket.
		/// </summary>
		/// <param name="buffer">The source buffer.</param>
		/// <param name="offset">Initial source offset.</param>
		/// <param name="length">Number of bytes to write.</param>
		public  void Write(byte[] buffer, int offset, int length) throws IOException
		{
			out.write(buffer, offset, length);
			out.flush();
		}

		/// <summary>
		/// Writes all bytes in the buffer to socket.
		/// </summary>
		/// <param name="buffer">the source buffer.</param>
		/// <returns>Number of written bytes.</returns>
		public void Write(byte[] buffer) throws IOException
		{
			out.write(buffer);
			out.flush();
		}

		public void Flush() throws IOException
		{
			out.flush();
		}
		
		public void SetTimeout(int ReceiveTimeout) {
			try {
				socket.setSoTimeout(ReceiveTimeout);
			} catch (Exception e) {}
		}
		
	}
