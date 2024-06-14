# Crypto_project

Through this project I aim at explaining few concepts about cryptography I have learnt along the way. 
It is NOT a programming excercise, I am not showcasing my ability in writing C code, it is out of scope. What I want to exaplain are few cool concepts I understood while programming.


## Project Details

Me and my friend have been asked to code a Bullettin Board System: a place where users register, login and post what they are thinking; the hard part is the security requirements 
the project has to fullfil.

+ Never store or transmit passwords in the clear.
+ Fulfill confidentiality, integrity, no-replay, and non-malleability in communications.
+ Guarantee perfect forward secrecy (PFS).

Seems fun, let's start.


## BOM: Bill of Materials

### Password storage

First things first: how do you guarantee that passwords are not stored in the clear? Exactly! **HASH**

What we did is hashing the pw created by the users with **SHA-256** and salting them with a random salt generated.

How did we gerate a random salt? We used the **[1]arc4random_uniform()** function. Thsi function is found in BSD library and uses the ChaCha20 stream cipher.


What is cool to note here is the usage of **salt**. It is a random string that gets added to the password before it gets hashed. This way, if someone gets access to a db it is not possible to tell if 2 users have the same passwords, given that the salt was different (random).

Salting makes brute force attack more complex because for every combination of the password you need to add every combination of the salt, so a b-bit long salt adds 2^b complexity.
In addition, salting makes **Dictionary attacks** and **Rainbow-Table** attacks more difficult to pursue.


### Data in transit

After establishing a secure session, client and servers start exchanging data. How do we secure the data flow? We use **AES-GCM 128 bit***. GCM is an encryption mode for AES that
stands for Galois Counter Mode. It guarantees confidentiality and authentication of the messages since is uses TAGS that are computed at the receiving end against the ones received 
to see if the data sent is the same as the data received. It also guarantees authentication for messages not intended to be ecnrypted (AAD) but we do not use it in this way.


## Key agreement and Key Exchanging protocol

Here it comes the best part. Since we must gurantee Perfect Forward Secrecy and protection against MiTM and Replay attack, we devised a method that incorporate a sort of ***digital signature*** and ***Ephemeral Diffie-Hellman*** for key derivation.

It is important to note that some of the initial assumptions were the fact that the client already knows the public key (RSA) of the server and we don't need to do do client authentication at the key level, just to implement it via a registration form (more on that later).







## References
[1]https://man.openbsd.org/arc4random











