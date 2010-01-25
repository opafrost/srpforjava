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
 * POJO for holding the random salt and verifier<br>
 *
 * @author Jordan Zimmerman - jordan@jordanzimmerman.com
 * @see SRPFactory Full Documentation
 * @version 1.1
 */
public class SRPVerifier implements Serializable
{
	public SRPVerifier(BigInteger verifier, BigInteger salt)
	{
		this.verifier_v = verifier;
		this.salt_s = salt;
	}

	/**
	 * v
	 */
	public final BigInteger 	verifier_v;

	/**
	 * s
	 */
	public final BigInteger 	salt_s;
}
