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
 * Runner for clients.<br>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.3 Some session methods now throw an authentication exception instead of returning true/false 2/21/07
 * @version 1.2 Updated to use the SRP-6 spec 2/21/07
 * @version 1.1
 */
public class SRPClientSessionRunner implements SRPRunner
{
	public SRPClientSessionRunner(SRPClientSession session)
	{
		fSession = session;
		fState = State.INIT;
		fSuccess = false;
		fOutput = null;
		fInput = null;
	}

	public boolean needsInput()
	{
		return fState != State.DONE;
	}

	public void setInput(BigInteger i)
	{
		fInput = i;
	}

	public boolean hasOutput()
	{
		return (fOutput != null);
	}

	public BigInteger getOutput()
	{
		return fOutput;
	}

	public boolean 			next() throws SRPAuthenticationFailedException
	{
		switch ( fState )
		{
			case INIT:
			{
				fOutput = null;
				fState = State.INPUT_S;
				break;
			}

			case INPUT_S:
			{
				fState = State.INPUT_B;
				fSession.setSalt_s(fInput);
				fOutput = fSession.getPublicKey_A();
				break;
			}

			case INPUT_B:
			{
				fState = State.INPUT_M2;
				fSession.setServerPublicKey_B(fInput);
				fOutput = fSession.getEvidenceValue_M1();
				break;
			}

			case INPUT_M2:
			{
				fOutput = null;
				fState = State.DONE;
				fSession.validateServerEvidenceValue_M2(fInput);
				fSuccess = true;
				break;
			}

			default:
			case DONE:
			{
				// do nothing
				break;
			}
		}

		return fState != State.DONE;
	}

	public BigInteger 			getValue()
	{
		return fOutput;
	}

	public boolean				success()
	{
		return fSuccess;
	}

	public byte[] 				getSessionKey()
	{
		return fSession.getSessionKey_K();
	}

	private enum State
	{
		INIT,
		INPUT_S,
		INPUT_B,
		INPUT_M2,
		DONE
	}

	private SRPClientSession 	fSession;
	private State 				fState;
	private boolean				fSuccess;
	private BigInteger 			fOutput;
	private BigInteger 			fInput;
}
