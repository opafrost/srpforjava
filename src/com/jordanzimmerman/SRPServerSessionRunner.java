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
 * runner for server sessions<br>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.3 Some session methods now throw an authentication exception instead of returning true/false 2/21/07
 * @version 1.2 Updated to use the SRP-6 spec 2/21/07
 * @version 1.1
 */
public class SRPServerSessionRunner implements SRPRunner
{
	public SRPServerSessionRunner(SRPServerSession session)
	{
		fSession = session;
		fState = State.OUTPUT_S;
		fSuccess = false;
		fOutput = null;
		fInput = null;
	}

	public boolean needsInput()
	{
		return (fState == State.INPUT_A) || (fState == State.INPUT_M1);
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

	public boolean			next() throws SRPAuthenticationFailedException
	{
		switch ( fState )
		{
			case OUTPUT_S:
			{
				fState = State.INPUT_A;
				fOutput = fSession.getVerifier().salt_s;
				break;
			}

			case INPUT_A:
			{
				fState = State.INPUT_M1;
				fSession.setClientPublicKey_A(fInput);
				fSession.computeCommonValue_S();
				fOutput = fSession.getPublicKey_B();
				break;
			}

			case INPUT_M1:
			{
				fSession.validateClientEvidenceValue_M1(fInput);
				fState = State.OUTPUT_M2;
				fSuccess = true;
				fOutput = fSession.getEvidenceValue_M2();
				break;
			}

			case OUTPUT_M2:
			{
				fState = State.DONE;
				fOutput = null;
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

	public byte[] 			getSessionKey()
	{
		return fSession.getSessionKey_K();
	}

	private enum State
	{
		OUTPUT_S,
		INPUT_A,
		INPUT_M1,
		OUTPUT_M2,
		DONE
	}

	private SRPServerSession 	fSession;
	private State 				fState;
	private boolean				fSuccess;
	private BigInteger 			fInput;
	private BigInteger 			fOutput;
}
