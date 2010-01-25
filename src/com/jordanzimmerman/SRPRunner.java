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

import java.math.BigInteger;

/**
 * General interface for running through a session.
 * <p>
 * Here is boilerplate code:
<code><pre>
 	SRPRunner		runner = ...
	while ( runner.next() )
	{
		if ( runner.hasOutput() )
		{
			BigInteger		output = runner.getOutput();
 			// TODO: send output to corresponding client/server
		}

		if ( runner.needsInput() )
		{
 			// TODO: get BigInteger from corresponding client/server
 			BigInteger		i = ... // read from client/server
			runner.setInput(i);
		}
	}

 	// at this point, runner.success() can be called to determine if authentication was successful.
</pre></code>
 * <p>
 * Released into the public domain
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory for boilerplate code
 * @version 1.3 Some session methods now throw an authentication exception instead of returning true/false 2/21/07
 * @version 1.2 Updated to use the SRP-6 spec 2/21/07
 * @version 1.1
 */
public interface SRPRunner
{
	/**
	 * Call until false is returned. Once false is returned, {@link #success()} can be checked and, if it returns true,
	 * {@link #getSessionKey()} can be used to encrypt communications.
	 *
	 * @return true/false
	 * @throws SRPAuthenticationFailedException if an exchanged value caused authentication to fail
	 */
	public boolean 			next() throws SRPAuthenticationFailedException;

	/**
	 * Returns true if an int from the corresponding client/server is needed to continue. {@link #setInput(java.math.BigInteger)} must be
	 * called before next() is called again.
	 *
	 * @return true/false
	 */
	public boolean			needsInput();

	/**
	 * Set the needed input for the next loop
	 *
	 * @param i the input (from the corresponding client/server)
	 */
	public void				setInput(BigInteger i);

	/**
	 * Returns true if there is an int that needs to be sent to the corresponding client/server. {@link #getOutput()} will return the int
	 * which should immediately be sent to the corresponding client/server.
	 *
	 * @return true/false
	 */
	public boolean			hasOutput();

	/**
	 * Return the int that needs to be sent to the corresponding client/server
	 *
	 * @return the int
	 */
	public BigInteger		getOutput();

	/**
	 * Returns true if authentication has succeeded. Only valid after {@link #next()} has returned false.
	 *
	 * @return true/false
	 */
	public boolean			success();

	/**
	 * If authentication has succeeded, this value can be used as an encryption key. Only valid after {@link #next()} has returned false and
	 * {@link #success()} has returned true.
	 *
	 * @return true/false
	 */
	public byte[]			getSessionKey();
}
