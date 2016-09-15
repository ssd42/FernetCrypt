Small python text encryption script.
Uses Fernet (Symmetric authenticated cryptography) which is fancy talk for uses a "secret key" to encrypt text files.

Other librarys are used such as:
* PBKDF2HMAC (used to generate a 32 char value from the provided string(secret key) by also salting it);
* Sha256 (used to hash the initial key multiple times to avoid use of rainbow tables)
* Standard python libraries

Simply prompts user for a key and generates the token key. After Prompts the user for the file to be encrypted and attaches a small "stamp" on it deferentiating it. 

