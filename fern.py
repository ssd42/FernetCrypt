# Librarys need for hashing and encryption
from cryptography.fernet import Fernet, MultiFernet, InvalidToken
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from hashlib import sha256 # this will become irrellevant with time

import os, base64, getpass


"""
NOTE: IF YOU USE THIS AND FORGET YOUR KEY BY ANY CHANCE THERE IS LITTLE TO NO CHANCE
THAT YOU WILL RECOVER WHAT YOU LOST MAKE SURE ITS A COMPLEX KEYPASS BUT NOTHING YOU'LL
FORGET.

TO-DO LIST

Implementations for future:
	*(DONE)Fcryp Extension -> Remove te _atlas.txt and give it it's own extension

	*Multi-Fernet -> in order to have an easy way for key rotation (main goal for folders)

	*(DONE)Folder-crypt -> en/decrypt an entire folder with the same key to save time

	*Text-line-crypt -> same thing as encryptFile but for a messge/string (for sending over a network)
"""

# extension for encrypted files, up to you but its this as default
extension = '.fcrypt'

# Global varible salt. Needs to be a byte for fernet to accept it, it is critical
salts = b'default_salt123'   
iterations = 10000
# Iterations in django limits itself to 3000 while using PBk... and sha215
# Take a look into the why of this though

# Find a way to avoid this
def wordInString(string, word):
	return string.replace(word, "", 1)


# User passes in a string to replace the default salt
def changeSalt(newSalt):
	global salts

	# To see if some wierd values are passed as a salt (i.e. base64)
	try:
		salts = bytes(str(newSalt).encode("utf-8"))
	except Exception as e:
		print(e)


def changeHashVal(newInt):
	global iterations

	if isinstance(newInt, int):
		iterations  = newInt
	else:
		raise ValueError("{} is not a compatible integer".format(newInt))


# Basic lookup functions.
def currSalt():
	print(salts)


def currHashVal():
	print(iterations)


# To incorporate in the multiFernet
def rotateKey(oldKey, newKey):
	pass


"""
Ok this is where it gets tricky, due to raibow tables and other methods i feel like hashing once isnt safe
enough, the current value feels forgettible so not so sure on it either. Since there is no server side
the amount of time it takes to calculate isnt all that bad.
With my crappy computer it takes between      seconds so shouldn't be that bad for others
"""

# With PBKDF2HMAC this code is no longer relevant feels like overkill and waste resources
# Hazmats primitive might make this code obsolete, but the hashes are objects that dont take arguments(which Im not sure how to deal with yet)

# Might have found a use in this but still feels unsafe. Still cute though might keep.
def hasher(psswrd):
	#extra line in case of encodings being needed
	code = psswrd

	#Crazy encoding properties the hazmat primitize objects spits out, reasearch later, also takes longer to hash than haslib about O(x^2)
	#code = psswrd.encode("utf8").strip()

	for _ in range(iterations):
		code = sha256(code.encode('utf-8')).hexdigest()

	#return code.decode("utf-8").strip()
	return code


def testTime():
	"""
	Small function to test time it takes for hasher to run. 
	"""
	from datetime import datetime
	now = datetime.now()

	hasher('Random string')

	print(datetime.now()-now)


# Uses PBKDF2HMAC to generate a salted key from the hashed password, this way guarenteeing its
# in the fernet standards and 2^5 characters every time.
def generateKey(key, salt):
	kdf = PBKDF2HMAC(
		algorithm=hashes.SHA256(),
		length=32,
		salt=salt,
		iterations=100000,
		backend=default_backend()
	)
	return base64.urlsafe_b64encode(kdf.derive(bytes(key.encode("utf-8"))))


"""
NOTE: THE NAME GENERATED FOR THE ENCRYPTED FILES IS JUST FOR THE SAKES OF TESTING IF YOU TRUELY WANT TI HIDE THEM
FEEL FREE TO REMOVE THOSE LINES OF CODE SINCE IT WILL WORK THE SAME
"""
# Not sure if I  should make the user pass their Fernet Obj or the key sinceit might be unsafe
# Since it will just be saved on the program
def encryptMessage(message, the_key):
	"""
	Generates the key, encodes to bytes, encrypts it and turns it back into a string
	"""
	fer = Fernet(generateKey(the_key, salts))
	byte_message = bytes(message.encode("utf-8"))
	return fer.encrypt(byte_message).decode('utf-8')	
	

def decryptMessage(message, the_key):
	try:
		fer = Fernet(generateKey(the_key, salts))
		byte_message = bytes(message.encode("utf-8"))
		return fer.decrypt(byte_message).decode('utf-8')

	# In the case the user and sender have different keys it will be safetly interrupted and promt to exit
	except (InvalidSignature, InvalidToken):
		print('Key you inputed does not match key from sender')





def encryptFile(the_file, the_key, changeKey = None):
	
	# Create a fernet object and generate a
	# fernet compatible key using global var salts.
	print('Output for testing')
	fer = Fernet(generateKey(the_key, salts))
	print(fer)

	with open(the_file) as file:
		the_message = file.read()

	# Covert message to byte to work with fernet
	byte_message = bytes(the_message.encode("utf-8"))

	# Generate a token of the encryted message to be written to the file and decode it
	token = fer.encrypt(byte_message)
	# Can't I just decode this top part
	token_string = token.decode('utf-8')

	# Creating name of encrypted file
	encrypt_name = os.path.splitext(the_file)[0] + extension

	# Attemps to write the ecrypted text to a new file and delete the old one.
	try:
		with open(encrypt_name, 'w') as afile:
			afile.write(token_string)

			os.remove(the_file)

	except Exception as e:
		print("Was not able to conclude due to:   {}".format(str(e)))

"""
use a extension fcrypt for example instead of _atlas.txt
seems cleaner and makes this look legit when we know im just a 2yo programmer

//best was of getting the extension out
fname = os.path.splitext(filename)[0]
fext = os.path.splitext(filename)[1]

"""

def decryptFile(the_file, the_key):
	# Create a fernet object and generate a
	# fernet compatible key using global var salts.
	fer = Fernet(generateKey(the_key, salts))

	with open(the_file) as file:
		the_message = file.read()

	# Covert message to byte to work with fernet
	byte_message = bytes(the_message.encode("utf-8"))

	# Generate a token of the encryted message to be written to the file and decode it
	token = fer.decrypt(byte_message)
	token_string = token.decode('utf-8')

	# Removing its crypt name and returning the original
	decrypt_name = os.path.splitext(the_file)[0] + '.txt'

	# Attempts to write the decrypted text and
	try:
		with open(decrypt_name, 'w') as afile:
			afile.write(token_string)
			os.remove(the_file)
	except Exception as e:
		print("Was not able to conclude due to: {}".format(str(e)))


# Basicly for faster encryption
def encryptDir(directory, the_key):
	os.chdir(directory)
	for file_name in os.listdir(directory):
		if file_name.endswith(".txt"):
			encryptFile(file_name, the_key)


# Same thing but for reverse
def decryptDir(directory, the_key):
	os.chdir(directory)
	for file_name in os.listdir(directory):
		if file_name.endswith(extension):
			decryptFile(file_name, the_key)


def main():
	# Irrelevant but stays for now
	password = hasher(getpass.getpass("Your key: "))

	ans = input("\nWant to encrypt/ decrypt file or encrypt/ decrypt a dir(e/d/edir/ddir): ")

	# Makes use of the functions above to either encrypt or decrypt (self explanitory delete this come on man)
	if ans.lower() == 'e':
		the_file = input("\nWhat is the file name: ")
		encryptFile(the_file, password)
		print("File was encrypted \n")

	elif ans.lower() == 'd':
		the_file = input("\nWhat is the file name: ")
		decryptFile(the_file, password)
		print("File was decrypted \n")

	elif ans.lower() == 'edir':
		the_dir = input("\nWhat is the dir path: ")
		encryptDir(the_dir, password)
		print("Directory was encrypted")

	elif ans.lower() == 'ddir':
		the_dir = input("\nWhat is the dir path: ")
		decryptDir(the_dir, password)
		print("Directory was decrypted")

	else:
		print("An error has occured: INVALID INPUT")

# Hopeing to turn this into a module
if __name__ == '__main__':
	main()