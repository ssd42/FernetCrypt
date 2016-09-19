# Librarys need for hashing and encryption
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from hashlib import sha256

# Used for in order of appearance: remove files from the folders, get the right size for the key, and secretly get pass
import os, base64, getpass



"""
NOTE: IF YOU USE THIS AND FORGET YOUR KEY BY ANY CHANCE THERE IS LITTLE TO NO CHANCE
THAT YOU WILL RECOVER WHAT YOU LOST MAKE SURE ITS A COMPLEX KEYPASS BUT NOTHING YOU'LL
FORGET.


Implementations for future:
	
	*Multi-Fernet -> in order to have an easy way for key rotation

	*Folder-crypt -> en/decrypt an entire folder with the same key to save time

	*Text-line-crypt -> same thing as encryptFile but for a messge/string (for sending over a network)
"""


# Global varible salt. Needs to be a byte for fernet to accept it, it is critical
# To be the same for decryption
# May be something simple since it can easily be seen
salts = b'yaya'   
hash_amount = 150000



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
	global hash_amount

	if isinstance(newInt, int):
		hash_amount  = newInt
	else:
		raise ValueError("{} is not a compatible integer".format(newInt))


# Basic lookup functions.
def currSalt():
	print(salts)


def currHashVal():
	print(hash_amount)


# To incororate in the multiFernet
def rotateKey(oldKey, newKey):
	pass


"""
Ok this is where it gets tricky, due to raibow tables and other methods i feel like hashing once isnt safe
enough, the current value feels forgettible so not so sure on it either. Since there is no server side
the amount of time it takes to calculate isnt all that bad.
With my crappy computer it takes between      seconds so shouldn't be that bad for others
"""
# Hazmats primitive might make this code obsolete, but the hashes are objects that dont take arguments(which Im not sure how to deal with yet)
def hasher(psswrd):
    #extra line in case of encodings being needed
	code = psswrd

	#Crazy encoding properties the hazmat primitize objects spits out, reasearch later, also takes longer to hash than haslib about Ox^2
    #code = psswrd.encode("utf8").strip()

	for _ in range(hash_amount):
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


def encryptFile(the_file, the_key):
	
	# Create a fernet object and generate a 
	# fernet compatible key using global var salts.
	fer = Fernet(generateKey(the_key, salts))

	with open(the_file) as file:
		the_message = file.read()

	# Covert message to byte to work with fernet
	byte_message = bytes(the_message.encode("utf-8"))

	# Generate a token of the encryted message to be written to the file and decode it
	token = fer.encrypt(byte_message)
	token_string = token.decode('utf-8')

    # Creating name of encrypted file
	encrypt_name = the_file[:-4] + '_atlas.txt'

    # Attemps to write the ecrypted text to a new file and delete the old one.
	try:
		with open(encrypt_name, 'w') as afile:
			afile.write(token_string)
        
			os.remove(the_file)
    
	except Exception as e:
		print("Was not able to conclude due to:   {}".format(str(e)))


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
	decrypt_name = wordInString(the_file[:-4], '_atlas') + '.txt'

	# Attempts to write the decrypted text and 
	try:
		with open(decrypt_name, 'w') as afile:
			afile.write(token_string)
			os.remove(the_file)
	except Exception as e:
		print("Was not able to conclude due to: {}".format(str(e)))


def main():
	# gets the user password
	password = hasher(getpass.getpass("Your key: "))


	ans = input("\nWant to (e)ncrypt or (d)ecrypt file (e/d): ")

	# Makes use of the functions above to either encrypt or decrypt (self explanitory delete this come on man)
	if ans.lower() == 'e':
		the_file = input("\nWhat is the file name: ")
		encryptFile(the_file, password)
		print("File was encrypted \n")

	elif ans.lower() == 'd':
		the_file = input("\nWhat is the file name: ")
		decryptFile(the_file, password)
		print("File was decrypted \n")
    
	else:
		print("An error has occured")


# Note for me: very usefull will only execute main if this file is executed
# If imported will not do anything
if __name__ == '__main__':
	main()