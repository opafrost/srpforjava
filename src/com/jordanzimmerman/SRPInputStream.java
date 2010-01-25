/*
 * Copyright 2008-2010 Jordan Zimmerman
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.jordanzimmerman;     

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;
import java.io.EOFException;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * An Output Stream that authenticates and encrypts (using AES). All read() methods process encrypted data using the active
 * SRP session key. This class assumes an {@link SRPOutputStream} on the other end.
 * <p>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.4 Bug reported by frederic barachant. read(byte[], int, int) needs to return -1 if the stream is closed - 6/18/09
 * @version 1.3 Updated to use the SRP-6 spec 2/21/07
 * @version 1.2 Fixed the implementation of {@link #read(byte[], int, int)} - 2/20/07
 * @version 1.1
 */
public class SRPInputStream extends InputStream
{
	/**
	 * @param in input stream to pipe from
	 */
	public SRPInputStream(InputStream in)
	{
		fIn = in;
		fSessionKey = null;
		fCipher = null;

		fBuffer = ByteBuffer.wrap(new byte[SRPInputStream.BUFFER_SIZE]);
		fBuffer.clear();
		fBuffer.flip();	// denote buffer as being empty
	}

	/**
	 * Must be called before any other method. This will completely authenticate to the corresponding client/server.
	 *
	 * @param runner A session runner
	 * @param out an output stream to the corresponding client/server.
	 * @throws IOException if authentication fails or there is an I/O error
	 */
	public synchronized void		authenticate(SRPRunner runner, SRPOutputStream out) throws IOException
	{
		while ( runner.next() )
		{
			if ( runner.hasOutput() )
			{
				out.writeAuthenticationValue(runner.getOutput(), true);
			}

			if ( runner.needsInput() )
			{
				runner.setInput(readAuthenticationValue(true));
			}
		}

		if ( !runner.success() )
		{
			throw new SRPAuthenticationFailedException("Authentication failed.");
		}

		fSessionKey = makeJCEKey(runner);

		try
		{
			fCipher = Cipher.getInstance(ENCRYPTION_TYPE);
			fCipher.init(Cipher.DECRYPT_MODE, fSessionKey);
		}
		catch ( GeneralSecurityException e )
		{
			IOException 		wrapped = new IOException();
			wrapped.initCause(e);
			throw wrapped;
		}
	}

	public synchronized int read() throws IOException
	{
		checkBuffer();
		return (fBuffer != null) ? (fBuffer.get() & 0xff) : -1;
	}

	public synchronized int read(byte b[]) throws IOException
	{
		return read(b, 0, b.length);
	}

	public synchronized int read(byte b[], int off, int len) throws IOException
	{
		boolean		firstByte = true;
		int			bytesRead = 0;
		while ( (fBuffer != null) && (len > 0) )
		{
			int		i = read();
			if ( i < 0 )
			{
				if ( bytesRead == 0 )
				{
					bytesRead = -1;
				}
				break;
			}

			++bytesRead;
			b[off++] = (byte)(i & 0xff);
			--len;

			if ( firstByte )
			{
				firstByte = false;
				if ( len > fBuffer.remaining() )
				{
					len = fBuffer.remaining();
				}
			}
		}
		return bytesRead;
	}

	public long skip(long n) throws IOException
	{
		IOException 	wrapped = new IOException();
		wrapped.initCause(new UnsupportedOperationException());
		throw wrapped;
	}

	public int available() throws IOException
	{
		return 0;
	}

	public synchronized void close() throws IOException
	{
		fIn.close();
	}

	public void mark(int readlimit)
	{
	}

	public void reset() throws IOException
	{
	}

	public boolean markSupported()
	{
		return false;
	}

	static final String			ENCRYPTION_TYPE = "AES";
	static final int			BUFFER_SIZE = 8192 - 5;		// 5 is enough to write the max value in Hex plus a newline

	BigInteger 	readAuthenticationValue(boolean required) throws IOException
	{
		StringBuilder		str = new StringBuilder();
		for(;;)
		{
			int		b = fIn.read();
			if ( b < 0 )
			{
				if ( required )
				{
					throw new SRPAuthenticationFailedException("Connection closed");
				}

				if ( str.length() == 0 )
				{
					return null;	// stream closed
				}
				throw new EOFException();
			}

			char	c = (char)(b & 0xff);
			if ( c == '\n' )
			{
				break;
			}

			str.append(c);
		}
		return new BigInteger(str.toString(), 16);
	}

	static Key 		makeJCEKey(SRPRunner runner)
	{
		byte[]			hash = runner.getSessionKey();
		return new SecretKeySpec(hash, ENCRYPTION_TYPE);
	}

	private void	checkBuffer() throws IOException
	{
		if ( fBuffer.hasRemaining() )
		{
			return;
		}

		if ( fSessionKey == null )
		{
			throw new IOException("authenticate() has not been called");
		}

		BigInteger 		sizeBigInt = readAuthenticationValue(false);
		byte[]			buffer = null;
		if ( sizeBigInt == null )
		{
			fBuffer = null;
		}
		else
		{
			int				size = sizeBigInt.intValue();
			buffer = new byte[size];
			int				offset = 0;
			while ( size > 0 )
			{
				int		bytesRead = fIn.read(buffer, offset, buffer.length - offset);
				if ( bytesRead < 0 )
				{
					fBuffer = null;
					break;
				}

				size -= bytesRead;
				if ( size < 0 )
				{
					throw new EOFException();
				}
			}
		}

		if ( (fBuffer != null) && (buffer != null) )
		{
			try
			{
				byte[]		decryptedBytes = fCipher.doFinal(buffer);
				fBuffer = ByteBuffer.wrap(decryptedBytes);
				fBuffer.rewind();
			}
			catch ( GeneralSecurityException e )
			{
				IOException 		wrapped = new IOException();
				wrapped.initCause(e);
				throw wrapped;
			}
		}
	}

	private InputStream 		fIn;
	private Cipher 				fCipher;
	private Key 				fSessionKey;
	private ByteBuffer 			fBuffer;
}
