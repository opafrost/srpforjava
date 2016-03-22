An implementation of SRP - Secure Remote Password Protocol. See http://srp.stanford.edu and http://srp.stanford.edu/ndss.html.

SRP attempts to eliminate many of the security problems involved in a client/server user authentication. I don't understand the math, but the ideas are fairly simple. On the server, store a mathematically generated number that is based on a user chosen password and a randomly generated "salt". Both the client and server maintain a predetermined prime number "N" and a "primitive root" based on N called "g". The nature of all these numbers allows an authentication without the server needing to save the password. The client asks for the salt that was created, then a series of calculations are performed with the client and server exchanging the calculated values. At the end of this, both the client and server can safely know that authentication has occurred.

From the SRP website, SRP assures:

  1. No useful information about the password P or its associated private key x is revealed during a successful run. Specifically, we wish to prevent an attacker from being able to guess and verify passwords based on exchanged messages.
  1. No useful information about the session key K is revealed to an eavesdropper during a successful run. Since K is a cryptographically strong key instead of a limited-entropy password, we are not concerned about guessing attacks on K, as long as K cannot be computed directly by an intruder.
  1. Even if an intruder has the ability to alter or create his own messages and make them appear to originate from Carol or Steve, the protocol should prevent the intruder from gaining access to the host or learning any information about passwords or session keys. At worst, an intruder should only be able to cause authentication to fail between the two parties (often termed a denial-of-service attack).
  1. If the host's password file is captured and the intruder learns the value of v, it should still not allow the intruder to impersonate the user without an expensive dictionary search.
  1. If the session key of any past session is compromised, it should not help the intruder guess at or otherwise deduce the user's password.
  1. If the user's password itself is compromised, it should not allow the intruder to determine the session key K for past sessions and decrypt them. Even present sessions should at least be protected from passive eavesdropping.

IMPORTANT: This library relies on JCE