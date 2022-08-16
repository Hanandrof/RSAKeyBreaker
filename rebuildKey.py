
"""
Created on Sun Jun 19 09:58:15 2022

@author: alexi
"""
import base64
import re
import sys
import math
from Crypto.PublicKey import RSA
from Crypto.Util import number
from optparse import OptionParser

#https://stackoverflow.com/questions/51716916/built-in-module-to-calculate-the-least-common-multiple
def lcm(a, b):
    return abs(a*b) // math.gcd(a, b)

#https://stackoverflow.com/questions/4798654/modular-multiplicative-inverse-function-in-python
def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m
    
parser = OptionParser()
parser.add_option("-i", "--in", action="store", type="string",dest="inputName",
                  help="Private Key Input Name")
parser.add_option("-o", "--out", action="store", type="string",dest="outputName",
                  default="output.key", help="Private Key Output Name")
(options, args) = parser.parse_args()

#Open mean key file
print("[x] Opening Broken Private Key File")
f = open(options.inputName, "r")
print(f"[~] Output from file\n{f.read()}");
f.seek(0)

#Extracts the actual private key and places it into a string
privateKey = ""
for x in f:
        if "PRIVATE KEY" not in x:
                privateKey = privateKey + x[:-1]
f.close()
print(f"[x] Reading private key\t\t\"{privateKey[:25]}...\"")

#Decodes from Base64 and puts into a byte array
privateKeyB64 = privateKey.encode("ascii")
privateKeyB64Bytes = base64.b64decode(privateKeyB64)
print(f"[x] Decoded private key \n    & converted to hex \t\t\"{privateKeyB64Bytes.hex()[:25]}...\"")

#Converts the byte array into hex
hexPrivateKey = privateKeyB64Bytes.hex()
#Splits the hex string based off of a commond delimiter in the RSA key
#Almost every parameter is seperated commonly by a hex string in the form of '02 8X'
#Where X can be a number from 0-2
#regex split using '+?' which looks for one single 8 behind the 2 and then looks for 0-2 behind the 8
hexPrivateKeyList = re.split('(028+?[0-2])',hexPrivateKey)
modAndE = re.split('(0203)', hexPrivateKeyList[2])
#mod = int(modAndE[0][6:],16)
e = int(modAndE[-1],16)
prime1 = int(hexPrivateKeyList[6][2:],16)
prime2 = int(hexPrivateKeyList[8][2:],16)
mod = prime1*prime2

#Calculates LCM of both primes -1
lcm=lcm(prime1-1,prime2-1)
#Calculates the private exponent
d=modinv(e,lcm)
u = number.inverse(prime1, prime2)

#Generates a new key
newKey = RSA.construct((mod,e,d,prime1,prime2, u))
regenKey = newKey.exportKey()
print(regenKey.decode("utf-8"))
print(f"[x] Placing rebuilt key into {options.outputName}")
with open(options.outputName, 'w') as f:
    f.write(regenKey.decode("utf-8"))