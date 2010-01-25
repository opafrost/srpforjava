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
 * Manages a client SRP session
 * <p>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.4 Make sure safeguards are checked: abort if B == 0 (mod N) or u == 0 - 2/27/07
 * @version 1.3 Updated to use the SRP-6 spec - 2/21/07
 * @version 1.2
 */
public class SRPClientSession
{
	/**
	 * @param constants constants to use
	 * @param password password as passed to {@link SRPFactory#makeVerifier(byte[])} 
	 */
	public SRPClientSession(SRPConstants constants, byte[] password)
	{
		fConstants = constants;
		fPassword = password;
	}

	/**
	 * Once the server sends the salt (value s in the docs), call this method to save the value
	 *
	 * @param salt salt from the server
	 */
	public void				setSalt_s(BigInteger salt)
	{
		fPrivateKey_x = SRPUtils.makePrivateKey(fPassword, salt);
		fRandom_a = SRPUtils.random(fConstants);
		fCommonValue_S = null;
		fEvidenceValue_M1 = null;
		fSessionKey_K = null;

		// A = g^a
		fPublicKey_A = fConstants.primitiveRoot_g.modPow(fRandom_a, fConstants.largePrime_N);
	}

	/**
	 * Returns the public key (value A in the docs). This should be passed to the server
	 *
	 * @return A
	 */
	public BigInteger		getPublicKey_A()
	{
		return fPublicKey_A;
	}

	/**
	 * Call to save the public key (value B in the docs) when received from the server
	 *
	 * @param publicKey_B B
	 * @throws SRPAuthenticationFailedException if B is invalid
	 */
	public void				setServerPublicKey_B(BigInteger publicKey_B) throws SRPAuthenticationFailedException
	{
		if ( fPublicKey_A == null )
		{
			throw new IllegalStateException("setSalt_s() has not been called yet.");
		}

		if ( publicKey_B.mod(fConstants.largePrime_N).equals(BigInteger.ZERO) )
		{
			throw new SRPAuthenticationFailedException("B%N == 0");
		}

		BigInteger		SRP6_u = SRPUtils.calc_u(fPublicKey_A, publicKey_B);
		if ( SRP6_u.mod(fConstants.largePrime_N).equals(BigInteger.ZERO) )
		{
			throw new SRPAuthenticationFailedException("u%N == 0");
		}

		// S = (B - 3(g^x))^(a + ux)
		BigInteger		three_g_pow_x = fConstants.srp6Multiplier_k.multiply(fConstants.primitiveRoot_g.modPow(fPrivateKey_x, fConstants.largePrime_N));
		BigInteger		B_minus_g_pow_x = publicKey_B.subtract(three_g_pow_x);
		BigInteger		ux = SRP6_u.multiply(fPrivateKey_x);
		fCommonValue_S = B_minus_g_pow_x.modPow(fRandom_a.add(ux), fConstants.largePrime_N).mod(fConstants.largePrime_N);
		fEvidenceValue_M1 = SRPUtils.calcM1(fPublicKey_A, publicKey_B, fCommonValue_S);

		// the MD5 output is the same as the AES key length
		fSessionKey_K = SRPUtils.hashToBytesMD5(fCommonValue_S);
	}

	/**
	 * After the session key has been computed, use this method to return the evidence value to send to the server (value M[1] in the docs).
	 *
	 * @return M(1)
	 */
	public BigInteger		getEvidenceValue_M1()
	{
		if ( fEvidenceValue_M1 == null )
		{
			throw new IllegalStateException("computeCommonValue_S() has not been called yet.");
		}

		return fEvidenceValue_M1;
	}

	/**
	 * When the server sends M(2), call this method to validate the number.
	 *
	 * @param evidenceValueFromServer_M2 M(2) from the server.
	 * @throws SRPAuthenticationFailedException if M(2) is incorrect
	 */
	public void validateServerEvidenceValue_M2(BigInteger evidenceValueFromServer_M2) throws SRPAuthenticationFailedException
	{
		if ( fEvidenceValue_M1 == null )
		{
			throw new IllegalStateException("computeCommonValue_S() has not been called yet.");
		}

		BigInteger 		M2 = SRPUtils.calcM2(fPublicKey_A, fEvidenceValue_M1, fCommonValue_S);
		if ( !evidenceValueFromServer_M2.equals(M2) )
		{
			throw new SRPAuthenticationFailedException("M(2) is incorrect");
		}
	}

	/**
	 * Returns the session common value which is the pre-hashed version of K
	 *
	 * @return common value
	 */
	public BigInteger 	getSessionCommonValue()
	{
		return fCommonValue_S;
	}

	/**
	 * The 16 byte session key suitable for encryption
	 *
	 * @return session key - K
	 */
	public byte[] 		getSessionKey_K()
	{
		return fSessionKey_K;
	}

	SRPConstants		getConstants()
	{
		return fConstants;
	}

	private SRPConstants 		fConstants;
	private byte[] 				fPassword;
	private BigInteger 			fPrivateKey_x;
	private BigInteger 			fRandom_a;
	private BigInteger 			fPublicKey_A;
	private BigInteger 			fCommonValue_S;
	private byte[]	 			fSessionKey_K;
	private BigInteger 			fEvidenceValue_M1;
}
