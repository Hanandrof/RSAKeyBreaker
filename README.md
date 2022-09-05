# RSAKeyBreaker
Breaks RSA Key's to create a small coding challenge

## DestroyKey.py
The destroy key script is used for producing the broken private RSA key that will be given to students via the pastebin. This program can be used to produce and break an original key, but for the sake of the ransomware environment we’ll need to feed an existing key into the script. We’ll take our private.pem file and have the script spit out our broken key with whatever name we choose with the command:
```bash
Python ./DestroyKey.py i private.pem -o newname.pem -s
```
### Step-by-Step
First we either open an inputted RSA key and import it into pycryptodome or we generate a private RSA Key using pycryptodome and export it to a file.

```python
if options.inputName is not None:    
    print("[x] Opening Private Key File")
    f = open(options.inputName, "r")
    key = RSA.import_key(f.read())
else:
    print("[x] Generating Private Key")
    key = RSA.generate(2048)
    print(key.exportKey().decode("utf-8"))
    print("[x] Writing new key to 'original.key'")
    with open('original.key', 'wb') as f:
        f.write(key.exportKey())
```

We then take the key that was either generated or read from a file and construct a new key using all of the original key components except for modulus. The modulus will be replaced with a base64 encoded sentence or with nothing dependent on the command line arguments passed.

```python
print("[x] Generating Problematic Key")
if options.sentence:
    newKey = RSA.construct((purnell,key.e,key.d,key.p,key.q,key.u),False)
else:
    newKey = RSA.construct((0,key.e,key.d,key.p,key.q,key.u),False)
```
 
Finally we export this key into a new file
```python
meanKey = newKey.exportKey()

#output the private key
print(f"[x] Placing broken key into {options.outputName}")
with open(options.outputName, 'w') as f:
    f.write(meanKey.decode("utf-8"))
```

## RebuildKey.py
This script represents the suggested route that students will need to take in order to reconstruct their broken private RSA key. It will generate the unbroken key which should mirror the content of the original private.pem file perfectly. DO NOTE that this file will be in .key format, and this is fine. However, if you plan to test the rebuilt key with Decrypt_fernet_key.py, you’ll need to rename the file to ‘private.pem’ (you can add the -o option to make it output in your preferred format). The command for this script is as follows:
```bash
Python ./rebuildKey.py -i newname.pem 
```
### Step-by-Step
First the rebuild key will open the private key file and extract the private key from the file

```python
print("[x] Opening Broken Private Key File")
f = open(options.inputName, "r")

#Extracts the actual private key and places it into a string
privateKey = ""
for x in f:
        if "PRIVATE KEY" not in x:
                privateKey = privateKey + x[:-1]
f.close()
```

This code above (hacky) adds every line of the base64 encoded private key to the privateKey string. Next it converts the privatekey string into a base64 decoded byte array and then converts that to a hex string.

```python
privateKeyB64 = privateKey.encode("ascii")
privateKeyB64Bytes = base64.b64decode(privateKeyB64)

#Converts the byte array into hex
hexPrivateKey = privateKeyB64Bytes.hex()
```

Next it will split the hexstring using regex. RSA keys use the value “02 8x” where x can be a value from 0-2 that seperates the different variables in the RSA Private key. Parsing this, we are able to get the different variables from the RSA key and reconstruct the modulus (mod = p*q).

```python
hexPrivateKeyList = re.split('(028+?[0-2])',hexPrivateKey)
modAndE = re.split('(0203)', hexPrivateKeyList[2])
e = int(modAndE[-1],16)
prime1 = int(hexPrivateKeyList[6][2:],16)
prime2 = int(hexPrivateKeyList[8][2:],16)
mod = prime1*prime2
```

Finally, using Pycryptodome we can reconstruct the RSA key using ‘RSA.construct as seen below.

```python
newKey = RSA.construct((mod,e,d,prime1,prime2, u))
regenKey = newKey.exportKey()
with open(options.outputName, 'w') as f:
    f.write(regenKey.decode("utf-8"))
```

This code also calculates the private exponent for the RSA key (although unnecessary) given the format of destroyKey.py.
