An implementation of SRP-6a - Secure Remote Password Protocol. See http://srp.stanford.edu and http://srp.stanford.edu/ndss.html. The improvements described in SRP-6: Improvements and Refinements to the Secure Remote Password Protocol have been incorporated.

SRP attempts to eliminate many of the security problems involved in a client/server user authentication. I don't understand the math, but the ideas are farily simple. On the server, store a mathematically generated number that is based on a user chosen password and a randomly generated "salt". Both the client and server maintain a predetermined prime number "N" and a "primitive root" based on N called "g". The nature of all these numbers allows an authentication without the server needing to save the password. The client asks for the salt that was created, then a series of calculations are performed with the client and server exchanging the calculated values. At the end of this, both the client and server can safely know that authentication has occurred.

From the SRP website, SRP assures:
  * No useful information about the password P or its associated private key x is revealed during a successful run. Specifically, we wish to prevent an attacker from being able to guess and verify passwords based on exchanged messages.
  * No useful information about the session key K is revealed to an eavesdropper during a successful run. Since K is a cryptographically strong key instead of a limited-entropy password, we are not concerned about guessing attacks on K, as long as K cannot be computed directly by an intruder.
  * Even if an intruder has the ability to alter or create his own messages and make them appear to originate from Carol or Steve, the protocol should prevent the intruder from gaining access to the host or learning any information about passwords or session keys. At worst, an intruder should only be able to cause authentication to fail between the two parties (often termed a denial-of-service attack).
  * If the host's password file is captured and the intruder learns the value of v, it should still not allow the intruder to impersonate the user without an expensive dictionary search.
  * If the session key of any past session is compromised, it should not help the intruder guess at or otherwise deduce the user's password.
  * If the user's password itself is compromised, it should not allow the intruder to determine the session key K for past sessions and decrypt them. Even present sessions should at least be protected from passive eavesdropping.

Using this library:
For general use, you should only need to directly use these three classes: SRPFactory, SRPInputStream and SRPOutputStream. Besides these three, you will use two POJOs: SRPConstants and SRPVerifier

For all interactions, you obtain an SRPFactory via one of the static getInstance() methods. The no-args version uses default values for the prime number and primitive root. The other version allows you to specify values for these.

The first activity is to generate a "verifier" for a password. Given a password P, this is accomplished via the makeVerifier(byte[.md](.md)) method. E.g.
```
        SRPFactory.getInstance().makeVerifier(P);
```
This value should be stored away referenced via a username.

The second activity is a client/server session. On the server, allocate a SRPServerSessionRunner loaded with a session from newServerSession(SRPVerifier). On the client, allocate a SRPClientSessionRunner loaded with a session from newClientSession(byte[.md](.md)). Once you have a Session Runner, you can pass it to an SRPInputStream and an SRPOutputStream. For each of these streams, call both SRPInputStream.authenticate(SRPRunner, SRPOutputStream) and SRPOutputStream.authenticate(SRPRunner, SRPInputStream). Once authenticated, use them as you would any I/O stream. All I/O on these streams are encrypted using AES with the SRP session key as the encryption key.

Stream Protocol
The SRPInputStream/SRPOutStream authenticate using, essentially, the protocol as specified here: http://srp.stanford.edu/design.html. All values are sent as BigInteger.toString(int) with a radix of 16. The only difference is that the method to combine values is unique to this library (see SRPUtils.combine(BigInteger, BigInteger)). If at any point authentication fails, the stream is closed.
Once authentication is complete, the streams use the following protocol to send data:
```
	[data size][newline]
	[data]
```
"data size" is the number of bytes in the data block. The size is specified as radix 16 BigInteger. The data block is encrypted via AES using K as the key. K is an MD5 hash of S. A new data block is sent each time flush() is called on the output stream.

IMPORTANT: This library relies on JCE