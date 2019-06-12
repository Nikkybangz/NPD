## install:
## pip3 install python-gnupg
#
## note - gpg needs to be installed first:
## brew install gpg
## apt install gpg
#
## you may need to also:
## export GPG_TTY=$(tty)
#
#import gnupg
##import gpg
#gpg = gnupg.GPG()
#
## generate key
#input_data = gpg.gen_key_input(
#    name_email='me@email.com',
#    passphrase='passphrase',
#)
#key = gpg.gen_key(input_data)
#print(key)
#
## create ascii-readable versions of pub / private keys
#ascii_armored_public_keys = gpg.export_keys(key.fingerprint)
#ascii_armored_private_keys = gpg.export_keys(
#    keyids=key.fingerprint,
#    secret=True,
#    passphrase='passphrase',
#)
#
## export
#with open('mykeyfile.asc', 'w') as f:
#    f.write(ascii_armored_public_keys)
#    f.write(ascii_armored_private_keys)
#
## import
#with open('mykeyfile.asc') as f:
#    key_data = f.read()
#import_result = gpg.import_keys(key_data)
#
#for k in import_result.results:
#    print(k)
#
## encrypt file
#with open('plain.txt', 'rb') as f:
#    status = gpg.encrypt_file(
#        file=f,
#        recipients=['me@email.com'],
#        output='encrypted.txt.gpg',
#    )
#
#print(status.ok)
#print(status.status)
#print(status.stderr)
#print('~'*50)
#
## decrypt file
#with open('encrypted.txt.gpg', 'rb') as f:
#    status = gpg.decrypt_file(
#        file=f,
#        passphrase='passphrase',
#        output='decrypted.txt',
#    )
#
#print(status.ok)
#print(status.status)
#print(status.stderr)


#!/usr/bin/python3.4
# requires pgpy >=0.4.0 (latest, as of 06/30/2016)
import warnings
import pgpy
from pgpy.constants import PubKeyAlgorithm, KeyFlags, HashAlgorithm, SymmetricKeyAlgorithm, CompressionAlgorithm
"""
  @01-05-2018
Reference link : https://pythonexample.com/code/pgpy/
"""
class Encryption:
  @staticmethod
  def get_key(name, plain=False):
    try:
      key = pgpy.PGPKey.from_file('{}.asc'.format(name))[0]
      return str(key) if plain else key
    except:
      return None
 
  @staticmethod
  def generate_certificates():
    """
    Will create two PGP pairs inside current folder. one named first.asc, second one second.asc 
    NAME will be used as name of the owner.
 
    Both private (key) and public (key.pubkey) keys will be stored in each file.
    """
    NAME = "Tester"
    for pair_name in ['first', 'second']:
      key = pgpy.PGPKey.new(PubKeyAlgorithm.RSAEncryptOrSign, 4096)
      uid = pgpy.PGPUID.new(NAME)
      key.add_uid(uid, 
        usage={KeyFlags.Sign, KeyFlags.EncryptCommunications, KeyFlags.EncryptStorage},
        hashes=[HashAlgorithm.SHA512],
        ciphers=[PubKeyAlgorithm.RSAEncryptOrSign, SymmetricKeyAlgorithm.AES256],
        compression=[CompressionAlgorithm.ZLIB, CompressionAlgorithm.BZ2, CompressionAlgorithm.ZIP, CompressionAlgorithm.Uncompressed])
      open('{}.asc'.format(pair_name), 'wb').write(bytes(key))#generate certificate and write on file
 
  @staticmethod
  def encrypt(data, key='first'):#Encrypt the incoming data with first public key file
    k = Encryption.get_key(key)
    m = k.pubkey.encrypt(pgpy.PGPMessage.new(data), cipher=SymmetricKeyAlgorithm.AES256)
    return bytes(m)
 
  @staticmethod
  def decrypt(data, key='first'):#Decrypt the incoming data with first private key file

    k = Encryption.get_key(key)
    with warnings.catch_warnings():
      warnings.simplefilter("ignore")
      m = k.decrypt(pgpy.PGPMessage.from_blob(data))
      return bytes(m._message.contents) if isinstance(m._message.contents, bytearray) else m._message.contents



























