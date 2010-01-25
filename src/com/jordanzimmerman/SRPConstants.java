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
import java.io.Serializable;

/**
 * POJO for holding the prime number and primitve root.<br>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.3 Updated to use the SRP-6a spec - k = H(N, g) 2/27/07
 * @version 1.2 Updated to use the SRP-6 spec 2/21/07
 * @version 1.1
 */
public class SRPConstants implements Serializable
{
	/**
	 * NOTE: this constructor validates the values passed via {@link SRPUtils#validateConstants(java.math.BigInteger,java.math.BigInteger)}
	 *
	 * @param largePrime a very large prime number
	 * @param primitiveRoot a primitive root that relates to the prime number.
	 */
	public SRPConstants(BigInteger largePrime, BigInteger primitiveRoot)
	{
		SRPUtils.validateConstants(largePrime, primitiveRoot);

		this.largePrime_N = largePrime;
		this.primitiveRoot_g = primitiveRoot;
		this.srp6Multiplier_k = SRPUtils.hash(SRPUtils.combine(this.largePrime_N, this.primitiveRoot_g));
	}

	/**
	 * N
	 */
	public final BigInteger 	largePrime_N;

	/**
	 * g
	 */
	public final BigInteger 	primitiveRoot_g;

	/**
	 * k from SRP-6
	 */
	public final BigInteger		srp6Multiplier_k;
}
