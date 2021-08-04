Chainbreaker2 - python 3
============
An updated version of the Chainbreaker2 repository, by making chainbreaker2 compatible for python 3.

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
## Install and run
You can either just run the code from source, or import it as a module and run as a module.
To run the code from source, just clone/download the sourcecode, make sure you have installed the dependencies and run ``chainbreaker.py`` as a script.

### Build the module
1) Navigate to the directory containing the file `setup.py`
2) Enter the command (from terminal): `$ python setup.py bdist_wheel -d dist`.
This creates a wheel file (extension: `.whl`) in the `/dist` folder.
3) Install the wheelfile with pip, or (if in the same directory containing `setup.py`) run: `$ pip install -e .`

### Running chainbreaker as a module
After succesfully installing the wheelfile, you can use the module from the command-line (allowing you to use input arguments) as follows:

```$ python -m chainbreaker```

Or you can import it nicely within other scripts like so:

```python
import chainbreaker 
keychain = chainbreaker.Chainbreaker('path/to/keychain/file/login.keychain', unlock_password='SecretPasswordHere')
```

And this returns a keychain object which you can use in your script.



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
                       [--output OUTPUT] [-d]
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
                        Only check to see if the provided unlock options work.
                        Exits 0 on success, 1 on failure.

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
  -d, --debug           Print debug information
```


## Example Usage
```
./chainbreaker.py --password=TestPassword -a test_keychain.keychain
2020-11-12 15:58:18,925 - INFO - 

ChainBreaker 2 - https://github.com/gaddie-3/chainbreaker

2020-11-12 15:58:18,925 - INFO - Runtime Command: chainbreaker.py --password=TestPassword -a test_keychain.keychain
2020-11-12 15:58:18,925 - INFO - Keychain: test_keychain.keychain
2020-11-12 15:58:18,925 - INFO - Keychain MD5: eb3abc06c22afa388ca522ea5aa032fc
2020-11-12 15:58:18,925 - INFO - Keychain 256: 2d76f564ac24fa6a8a22adb6d5cb9b430032785b1ba3effa8ddea38222008441
2020-11-12 15:58:18,925 - INFO - Dump Start: 2020-11-12 15:58:18.925479
2020-11-12 15:58:19,245 - INFO - 1 Keychain Password Hash
2020-11-12 15:58:19,245 - INFO - 	$keychain$*7255a69abe21a28e1d2967265c9bba9c9bf4daf1*28dcfa41552db4eb*9dbb91712bb6a38f46e1b4335c334d444eb0c451e51fa02183eafe05c35310d76014bc04b699d420d8487d4452d067e5
2020-11-12 15:58:19,245 - INFO - 
2020-11-12 15:58:19,245 - INFO - 2 Generic Passwords
2020-11-12 15:58:20,306 - INFO - 	[+] Generic Password Record
2020-11-12 15:58:20,306 - INFO - 	 [-] Create DateTime: 2020-10-13 23:01:17
2020-11-12 15:58:20,306 - INFO - 	 [-] Last Modified DateTime: 2020-10-13 23:01:17
2020-11-12 15:58:20,306 - INFO - 	 [-] Description: secure note
2020-11-12 15:58:20,306 - INFO - 	 [-] Creator: 
2020-11-12 15:58:20,306 - INFO - 	 [-] Type: note
2020-11-12 15:58:20,307 - INFO - 	 [-] Print Name: Test Secure Note
2020-11-12 15:58:20,307 - INFO - 	 [-] Alias: 
2020-11-12 15:58:20,307 - INFO - 	 [-] Account: 
2020-11-12 15:58:20,307 - INFO - 	 [-] Service: Test Secure Note
2020-11-12 15:58:20,307 - INFO - 	 [-] Base64 Encoded Password: PD94bWwgdmVyc2lvbj0iMS4wIiBlbmNvZGluZz0iVVRGLTgiPz4KPCFET0NUWVBFIHBsaXN0IFBVQkxJQyAiLS8vQXBwbGUvL0RURCBQTElTVCAxLjAvL0VOIiAiaHR0cDovL3d3dy5hcHBsZS5jb20vRFREcy9Qcm9wZXJ0eUxpc3QtMS4wLmR0ZCI+CjxwbGlzdCB2ZXJzaW9uPSIxLjAiPgo8ZGljdD4KCTxrZXk+Tk9URTwva2V5PgoJPHN0cmluZz5UaGlzIGlzIGEgdGVzdCBzZWN1cmUgbm90ZS4gSSBkb27igJl0IGtub3cgdGhhdCBDaGFpbmJyZWFrZXIgd2lsbCBiZSBhYmxlIHRvIHNlZSBpdOKApjwvc3RyaW5nPgoJPGtleT5SVEZEPC9rZXk+Cgk8ZGF0YT4KCWNuUm1aQUFBQUFBREFBQUFBZ0FBQUFjQUFBQlVXRlF1Y25SbUFRQUFBQzdUQVFBQUt3QUFBQUVBQUFETEFRQUFlMXh5CglkR1l4WEdGdWMybGNZVzV6YVdOd1p6RXlOVEpjWTI5amIyRnlkR1l5TlRFekNseGpiMk52WVhSbGVIUnpZMkZzYVc1bgoJTUZ4amIyTnZZWEJzWVhSbWIzSnRNSHRjWm05dWRIUmliRnhtTUZ4bWJtbHNYR1pqYUdGeWMyVjBNQ0JJWld4MlpYUnAKCVkyRk9aWFZsTFV4cFoyaDBPMzBLZTF4amIyeHZjblJpYkR0Y2NtVmtNalUxWEdkeVpXVnVNalUxWEdKc2RXVXlOVFU3CglYSEpsWkRCY1ozSmxaVzR3WEdKc2RXVXdPMzBLZTF3cVhHVjRjR0Z1WkdWa1kyOXNiM0owWW13N08xeGpjM055WjJKYwoJWXpCY1l6QmNZekJjWTI1aGJXVWdkR1Y0ZEVOdmJHOXlPMzBLWEhCaGNtUmNkSGcxTmpCY2RIZ3hNVEl3WEhSNE1UWTQKCU1GeDBlREl5TkRCY2RIZ3lPREF3WEhSNE16TTJNRngwZURNNU1qQmNkSGcwTkRnd1hIUjROVEEwTUZ4MGVEVTJNREJjCglkSGcyTVRZd1hIUjROamN5TUZ4d1lYSmthWEp1WVhSMWNtRnNYSEJoY25ScFoyaDBaVzVtWVdOMGIzSXdDZ3BjWmpCYwoJWm5NeU5pQmNZMll5SUZSb2FYTWdhWE1nWVNCMFpYTjBJSE5sWTNWeVpTQnViM1JsTGlCSklHUnZibHduT1RKMElHdHUKCWIzY2dkR2hoZENCRGFHRnBibUp5WldGclpYSWdkMmxzYkNCaVpTQmhZbXhsSUhSdklITmxaU0JwZEZ3bk9EVjlBUUFBCglBQ01BQUFBQkFBQUFCd0FBQUZSWVZDNXlkR1lRQUFBQXZUR0dYN1lCQUFBQUFBQUFBQUFBQUE9PQoJPC9kYXRhPgo8L2RpY3Q+CjwvcGxpc3Q+Cg==
2020-11-12 15:58:20,307 - INFO - 	
2020-11-12 15:58:20,307 - INFO - 
2020-11-12 15:58:20,331 - INFO - 	[+] Generic Password Record
2020-11-12 15:58:20,331 - INFO - 	 [-] Create DateTime: 2020-09-24 23:34:14
2020-11-12 15:58:20,331 - INFO - 	 [-] Last Modified DateTime: 2020-09-29 21:54:55
2020-11-12 15:58:20,331 - INFO - 	 [-] Description: 
2020-11-12 15:58:20,332 - INFO - 	 [-] Creator: 
2020-11-12 15:58:20,332 - INFO - 	 [-] Type: 
2020-11-12 15:58:20,332 - INFO - 	 [-] Print Name: Stored Test Password
2020-11-12 15:58:20,332 - INFO - 	 [-] Alias: 
2020-11-12 15:58:20,332 - INFO - 	 [-] Account: TestUser
2020-11-12 15:58:20,332 - INFO - 	 [-] Service: Stored Test Password
2020-11-12 15:58:20,332 - INFO - 	 [-] Password: TestPasswordValue123!
2020-11-12 15:58:20,332 - INFO - 	
2020-11-12 15:58:20,332 - INFO - 
2020-11-12 15:58:20,332 - INFO - 1 Internet Passwords
2020-11-12 15:58:20,356 - INFO - 	[+] Internet Record
2020-11-12 15:58:20,356 - INFO - 	 [-] Create DateTime: 2020-09-29 22:21:51
2020-11-12 15:58:20,356 - INFO - 	 [-] Last Modified DateTime: 2020-09-29 22:21:51
2020-11-12 15:58:20,356 - INFO - 	 [-] Description: 
2020-11-12 15:58:20,356 - INFO - 	 [-] Comment: 
2020-11-12 15:58:20,356 - INFO - 	 [-] Creator: 
2020-11-12 15:58:20,356 - INFO - 	 [-] Type: 
2020-11-12 15:58:20,356 - INFO - 	 [-] PrintName: example.com
2020-11-12 15:58:20,356 - INFO - 	 [-] Alias: 
2020-11-12 15:58:20,357 - INFO - 	 [-] Protected: 
2020-11-12 15:58:20,357 - INFO - 	 [-] Account: TestUsername
2020-11-12 15:58:20,357 - INFO - 	 [-] SecurityDomain: 
2020-11-12 15:58:20,357 - INFO - 	 [-] Server: example.com
2020-11-12 15:58:20,357 - INFO - 	 [-] Protocol Type: kSecProtocolTypeHTTPS
2020-11-12 15:58:20,357 - INFO - 	 [-] Auth Type: kSecAuthenticationTypeDefault
2020-11-12 15:58:20,357 - INFO - 	 [-] Port: 0
2020-11-12 15:58:20,357 - INFO - 	 [-] Path: 
2020-11-12 15:58:20,357 - INFO - 	 [-] Password: TestPassword123!
2020-11-12 15:58:20,357 - INFO - 	
2020-11-12 15:58:20,357 - INFO - 
2020-11-12 15:58:20,357 - INFO - 0 Appleshare Passwords
2020-11-12 15:58:20,357 - INFO - 0 Private Keys
2020-11-12 15:58:20,357 - INFO - 0 Public Keys
2020-11-12 15:58:20,357 - INFO - 1 x509 Certificates
2020-11-12 15:58:20,357 - INFO - 	[+] X509 Certificate
2020-11-12 15:58:20,357 - INFO - 	 [-] Print Name: Apple Root CA
2020-11-12 15:58:20,358 - INFO - 	 [-] Certificate: MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg++FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9wtj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IWq6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKMaLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8EBAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAEggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNlIG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBjb25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZpY2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBcNplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQPy3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4FgxhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oPIQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AXUKqK1drk/NAJBzewdXUh
2020-11-12 15:58:20,358 - INFO - 	
2020-11-12 15:58:20,358 - INFO - 
2020-11-12 15:58:20,358 - INFO - 

ChainBreaker 2 - https://github.com/gaddie-3/chainbreaker

2020-11-12 15:58:20,358 - INFO - Runtime Command: chainbreaker.py --password=TestPassword -a test_keychain.keychain
2020-11-12 15:58:20,358 - INFO - Keychain: test_keychain.keychain
2020-11-12 15:58:20,358 - INFO - Keychain MD5: eb3abc06c22afa388ca522ea5aa032fc
2020-11-12 15:58:20,358 - INFO - Keychain 256: 2d76f564ac24fa6a8a22adb6d5cb9b430032785b1ba3effa8ddea38222008441
2020-11-12 15:58:20,358 - INFO - Dump Start: 2020-11-12 15:58:18.925479
2020-11-12 15:58:20,358 - INFO - Dump Summary:
2020-11-12 15:58:20,358 - INFO - 	1 Keychain Password Hash
2020-11-12 15:58:20,358 - INFO - 	2 Generic Passwords
2020-11-12 15:58:20,358 - INFO - 	1 Internet Passwords
2020-11-12 15:58:20,358 - INFO - 	0 Appleshare Passwords
2020-11-12 15:58:20,358 - INFO - 	0 Private Keys
2020-11-12 15:58:20,359 - INFO - 	0 Public Keys
2020-11-12 15:58:20,359 - INFO - 	1 x509 Certificates
2020-11-12 15:58:20,359 - INFO - Dump End: 2020-11-12 15:58:20.358259
```

## Cracking the Keychain Hash using hashcat
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