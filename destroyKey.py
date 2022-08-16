import sys
from Crypto.PublicKey import RSA
from Crypto.Util import number
from optparse import OptionParser

#Checks for and parses input parameters
parser = OptionParser()
parser.add_option("-i", "--in", action="store", type="string",dest="inputName",
                  help="Private Key Input Name")
parser.add_option("-o", "--out", action="store", type="string",dest="outputName",
                  default="output.key", help="Private Key Output Name")
parser.add_option("-s", action="store_false", dest="sentence",
                  help="no sentence to modulus", default=True)
(options, args) = parser.parse_args()
    
#Sentence to replace d with
purnell = 0x526f6765722e2052656164206974206f75742e0a0a434150434f4d0a492e2e2e4920646f6e2774206765742069742c20466c696768742e204e6f207265616c0a7374617475732e204a75737420612073696e676c652073656e74656e63652e0a0a4252454e44414e0a576861742773206974207361793f0a0a434150434f4d0a4d6573736167652072656164733a2022486f7573746f6e2c20626520616476697365643a20526963680a5075726e656c6c206973206120737465656c792d65796564206d697373696c65206d616e2e220a0a4252454e44414e0a576861743f2057686f207468652068656c6c2069732052696368205075726e656c6c3f202020

#Generates and/or opens private key input file
if options.inputName is not None:    
    print("[x] Opening Private Key File")
    f = open(options.inputName, "r")
    key = RSA.import_key(f.read())
    print(key.exportKey().decode("utf-8"))
else:
    print("[x] Generating Private Key")
    key = RSA.generate(2048)
    print(key.exportKey().decode("utf-8"))
    print("[x] Writing new key to 'original.key'")
    with open('original.key', 'wb') as f:
        f.write(key.exportKey())

#Generate the private key
print("[x] Generating Problematic Key")
if options.sentence:
    newKey = RSA.construct((purnell,key.e,key.d,key.p,key.q,key.u),False)
else:
    newKey = RSA.construct((0,key.e,key.d,key.p,key.q,key.u),False)
print("[x] New Problematic Key Generated")
meanKey = newKey.exportKey()
print(meanKey.decode("utf-8"))

#output the private key
print(f"[x] Placing broken key into {options.outputName}")
with open(options.outputName, 'w') as f:
    f.write(meanKey.decode("utf-8"))

