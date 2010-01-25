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
import java.io.IOException;
import java.io.OutputStream;
import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.GeneralSecurityException;
import java.security.Key;

/**
 * An Output Stream that authenticates and encrypts (using AES). All write() methods process encrypted data using the active
 * SRP session key. This class assumes an {@link SRPInputStream} on the other end.
 * <p>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.2 Updated to use the SRP-6 spec 2/21/07
 * @version 1.1
 */
public class SRPOutputStream extends OutputStream
{
	/**
	 * @param out output stream to pipe to
	 */
	public SRPOutputStream(OutputStream out)
	{
		fOut = out;
		fSessionKey = null;
		fCipher = null;

		fBuffer = ByteBuffer.wrap(new byte[SRPInputStream.BUFFER_SIZE]);
		fBuffer.clear();
	}

	/**
	 * Must be called before any other method. This will completely authenticate to the corresponding client/server.
	 *
	 * @param runner A session runner
	 * @param in an input stream to the corresponding client/server.
	 * @throws IOException if authentication fails or there is an I/O error
	 */
	public synchronized void		authenticate(SRPRunner runner, SRPInputStream in) throws IOException
	{
		while ( runner.next() )
		{
			if ( runner.hasOutput() )
			{
				writeAuthenticationValue(runner.getOutput(), true);
			}

			if ( runner.needsInput() )
			{
				runner.setInput(in.readAuthenticationValue(true));
			}
		}

		if ( !runner.success() )
		{
			throw new SRPAuthenticationFailedException("Authentication failed.");
		}

		fSessionKey = SRPInputStream.makeJCEKey(runner);

		try
		{
			fCipher = Cipher.getInstance(SRPInputStream.ENCRYPTION_TYPE);
			fCipher.init(Cipher.ENCRYPT_MODE, fSessionKey);
		}
		catch ( GeneralSecurityException e )
		{
			IOException 		wrapped = new IOException();
			wrapped.initCause(e);
			throw wrapped;
		}
	}

	public synchronized void write(int b) throws IOException
	{
		checkBuffer(false);
		fBuffer.put((byte)(b & 0xff));
	}

	public synchronized void write(byte b[]) throws IOException
	{
		for ( byte i : b )
		{
			write(i & 0xff);
		}
	}

	public synchronized void write(byte b[], int off, int len) throws IOException
	{
		while ( len-- > 0 )
		{
			write(b[off++] & 0xff);
		}
	}

	public synchronized void flush() throws IOException
	{
		checkBuffer(true);
	}

	public synchronized void close() throws IOException
	{
		flush();
		fOut.close();
	}

	void			writeAuthenticationValue(BigInteger i, boolean flush) throws IOException
	{
		String		str = i.toString(16);
		for ( int j = 0; j < str.length(); ++j )
		{
			char		c = str.charAt(j);
			fOut.write(c & 0xff);
		}
		fOut.write('\n');
		if ( flush )
		{
			fOut.flush();
		}
	}

	private void	checkBuffer(boolean force) throws IOException
	{
		if ( !force && fBuffer.hasRemaining() )
		{
			return;
		}

		if ( fSessionKey == null )
		{
			throw new IOException("authenticate() has not been called");
		}

		fBuffer.flip();

		if ( fBuffer.limit() > 0 )
		{
			byte[] 		encryptedBytes;
			try
			{
				encryptedBytes = fCipher.doFinal(fBuffer.array(), 0, fBuffer.limit());
			}
			catch ( GeneralSecurityException e )
			{
				IOException 		wrapped = new IOException();
				wrapped.initCause(e);
				throw wrapped;
			}

			writeAuthenticationValue(BigInteger.valueOf(encryptedBytes.length), false);
			fOut.write(encryptedBytes);
			fOut.flush();
		}

		fBuffer.clear();
	}

	private OutputStream 	fOut;
	private Cipher 			fCipher;
	private ByteBuffer		fBuffer;
	private Key 			fSessionKey;
}
