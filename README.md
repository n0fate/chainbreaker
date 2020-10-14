Chainbreaker2
============

Chainbreaker can be used to extract the following types of information from an OSX keychain in a forensically sound manner: 

* Hashed Keychain password, suitable for cracking with [hashcat](https://hashcat.net/hashcat/) or
 [John the Ripper](https://www.openwall.com/john/)
* Internet Passwords
* Generic Passwords
* Private Keys
* Public Keys
* X509 Certificates
* Secure Notes
* Appleshare Passwords
 
Given the keychain unlock password, a master key obtained using [volafox](https://github.com/n0fate/volafox) or 
[volatility](https://github.com/volatilityfoundation/volatility), or an unlock file such as SystemKey, Chainbreaker will
also provide plaintext passwords.

Without one of these methods of unlocking the Keychain, Chainbreaker will display all other available information.

## Supported OS's
Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra, Mojave, Catalina

## Target Keychain file
Any valid .keychain or .keychain-db can be supplied. Common Keychain locations include: 
* User keychains, these can contain ID's, passwords, and other secure data pertaining to installed applications, ssh/vpn, mail, contacts, calendar
    * /Users/[username]/Library/Keychains/login.keychain
    * /Users/[username]/Library/Keychains/login.keychain-db

* System Keychains, these can contain WiFi passwords registered by the local machine and several certifications and public/private keys.
    * /Library/Keychains/System.keychain
        * Note: The unlock file for this keychain is commonly located at /var/db/SystemKey

## Help:
```
$ python ./chainbreaker.py --help
usage: chainbreaker.py [-h] [--dump-all] [--dump-keychain-password-hash]
                       [--dump-generic-passwords] [--dump-internet-passwords]
                       [--dump-appleshare-passwords] [--dump-private-keys]
                       [--dump-public-keys] [--dump-x509-certificates]
                       [--export-keychain-password-hash]
                       [--export-generic-passwords]
                       [--export-internet-passwords]
                       [--export-appleshare-passwords] [--export-private-keys]
                       [--export-public-keys] [--export-x509-certificates]
                       [--export-all] [--check-unlock-options]
                       [--password-prompt] [--password PASSWORD]
                       [--key-prompt] [--key KEY] [--unlock-file UNLOCK_FILE]
                       [--output OUTPUT] [-q] [-d]
                       keychain

Dump items stored in an OSX Keychain

positional arguments:
  keychain              Location of the keychain file to parse

optional arguments:
  -h, --help            show this help message and exit

Dump Actions:
  --dump-all, -a        Dump records to the console window.
  --dump-keychain-password-hash
                        Dump the keychain password hash in a format suitable
                        for hashcat or John The Ripper
  --dump-generic-passwords
                        Dump all generic passwords
  --dump-internet-passwords
                        Dump all internet passwords
  --dump-appleshare-passwords
                        Dump all appleshare passwords
  --dump-private-keys   Dump all private keys
  --dump-public-keys    Dump all public keys
  --dump-x509-certificates
                        Dump all X509 certificates

Export Actions:
  Export records to files. Save location is CWD, but can be overridden with
  --output / -o

  --export-keychain-password-hash
                        Save the keychain password hash to disk
  --export-generic-passwords
                        Save all generic passwords to disk
  --export-internet-passwords
                        Save all internet passwords to disk
  --export-appleshare-passwords
                        Save all appleshare passwords to disk
  --export-private-keys
                        Save private keys to disk
  --export-public-keys  Save public keys to disk
  --export-x509-certificates
                        Save X509 certificates to disk
  --export-all, -e      Save records to disk

Misc. Actions:
  --check-unlock-options, -c
                        Only check to see if the provided unlock options
                        work.Exits 0 on success, 1 on failure.

Unlock Options:
  --password-prompt, -p
                        Prompt for a password to use in unlocking the keychain
  --password PASSWORD   Unlock the keychain with a password, provided on the
                        terminal.Caution: This is insecure and you should
                        likely use--password-prompt instead
  --key-prompt, -k      Prompt for a key to use in unlocking the keychain
  --key KEY             Unlock the keychain with a key, provided via
                        argument.Caution: This is insecure and you should
                        likely use --key-prompt instead
  --unlock-file UNLOCK_FILE
                        Unlock the keychain with a key file

Output Options:
  --output OUTPUT, -o OUTPUT
                        Directory to output exported records to.
  -q, --quiet           Suppress all output
  -d, --debug           Print debug information
```


## Example Usage
```
./chainbreaker.py -a --password TestPassword ./test_keychain.keychain
Keychain Password Hash
	$keychain$*7255a69abe21a28e1d2967265c9bba9c9bf4daf1*28dcfa41552db4eb*9dbb91712bb6a38f46e1b4335c334d444eb0c451e51fa02183eafe05c35310d76014bc04b699d420d8487d4452d067e5


1 Generic Passwords
	[+] Generic Password Record
	 [-] Create DateTime: 2020-09-24 23:34:14
	 [-] Last Modified DateTime: 2020-09-29 21:54:55
	 [-] Description: 
	 [-] Creator: 
	 [-] Type: 
	 [-] Print Name: Stored Test Password
	 [-] Alias: 
	 [-] Account: TestUser
	 [-] Service: Stored Test Password
	 [-] Password: TestPasswordValue123!
	


1 Internet Passwords
	[+] Internet Record
	 [-] Create DateTime: 2020-09-29 22:21:51
	 [-] Last Modified DateTime: 2020-09-29 22:21:51
	 [-] Description: 
	 [-] Comment: 
	 [-] Creator: 
	 [-] Type: 
	 [-] PrintName: example.com
	 [-] Alias: 
	 [-] Protected: 
	 [-] Account: TestUsername
	 [-] SecurityDomain: 
	 [-] Server: example.com
	 [-] Protocol Type: kSecProtocolTypeHTTPS
	 [-] Auth Type: kSecAuthenticationTypeDefault
	 [-] Port: 0
	 [-] Path: 
	 [-] Password: TestPassword123!
	


0 Appleshare Passwords


0 Public Keys


0 Private Keys
```

##Cracking the Keychain Hash using hashcat
### Hash Extraction
The password used to encrypt a keychain can be dumped using the --dump-keychain-password-hash option.
```
$ ./chainbreaker.py --dump-keychain-password-hash ./test_keychain.keychain 
Keychain Password Hash
	$keychain$*7255a69abe21a28e1d2967265c9bba9c9bf4daf1*28dcfa41552db4eb*9dbb91712bb6a38f46e1b4335c334d444eb0c451e51fa02183eafe05c35310d76014bc04b699d420d8487d4452d067e5
```
### Hash Cracking
After obtaining the keychain password hash, you can use a program such as [hashcat](https://hashcat.net/hashcat/) to attempt to crack it.

```

> hashcat.exe -m 23100 --keep-guessing hashes.txt dictionary.txt
hashcat (v6.1.1) starting...

[...]

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Applicable optimizers applied:
* Zero-Byte
* Single-Hash
* Single-Salt
* Slow-Hash-SIMD-LOOP

[...]

$keychain$*7255a69abe21a28e1d2967265c9bba9c9bf4daf1*28dcfa41552db4eb*9dbb91712bb6a38f46e1b4335c334d444eb0c451e51fa02183eafe05c35310d76014bc04b699d420d8487d4452d067e5:TestPassword

Session..........: hashcat
Status...........: Cracked
Hash.Name........: Apple Keychain
Hash.Target......: $keychain$*7255a69abe21a28e1d2967265c9bba9c9bf4daf1...d067e5
[...]

```

*Note:* As described in [hashcat #2457](https://github.com/hashcat/hashcat/issues/2457) collisions are very common based on the current checks.
To combat this, you'll want to use the "--keep-guessing" flag, and keep trying the found passwords until you (hopefully) get the correct one.

## Extraction from memory images
Volofax can be used to extract Keychain files and master key candidates from memory images.


```
$ python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump

[+] Find MALLOC_TINY heap range (guess)
 [-] range 0x7fef03400000-0x7fef03500000
 [...]
 [-] range 0x7fef04900000-0x7fef04a00000

[*] Search for keys in range 0x7fef03400000-0x7fef03500000 complete. master key candidates : 0
[...]
[*] Search for keys in range 0x7fef04900000-0x7fef04a00000 complete. master key candidates : 6

[*] master key candidate: 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9
[...]
[*] master key candidate: 903C49F0FE0700C0133749F0FE0700404158544D00000000
 
$ ./chainbreaker.py --key 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9 ./test_keychain.keychain
```

Additional examples can be found in this [gist](https://gist.github.com/n0fate/790428d408d54b910956) by n0fate.

## Why the rewrite?
Chainbreaker2 was forked to be heavily refactored and modified from the original [chainbreaker](https://github.com/n0fate/chainbreaker).
 
The primary reason behind this fork is to add better support integration into third-party forensic platforms such as 
[Autopsy](https://www.autopsy.com/).  

During the refactor, additional functionality was added including: 
* Enhanced user control and options 
* Extraction of the Keychain hash for use with third-party hash cracking software.
* Dumping all available information, regardless of the presence of an unlocking method


## Credits
* Chainbreaker2 has been significantly refactored and with accitional functionality added by [Luke Gaddie](luke@socially-inept.net)
* The original author of [chainbreaker](https://github.com/n0fate/chainbreaker) is [n0fate](http://twitter.com/n0fate) 

## License
[GNU GPL v2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)

## TODO
* Better commenting of code.
* Better documentation of the keychain format.