This branch contains a quick patch for chainbreaker to dump non-exportable keys on High Sierra, see README-keydump.txt for more details. Original README goes below.

chainbreaker
============

The chainbreaker can extract user credential in a Keychain file with Master Key or user password in forensically sound manner.
Master Key candidates can be extracted from [volafox](https://github.com/n0fate/volafox) or [volatility](https://github.com/volatilityfoundation/volatility) keychaindump module.

## Supported OS
Snow Leopard, Lion, Mountain Lion, Mavericks, Yosemite, El Capitan, (High) Sierra

## Target Keychain file
* User Keychain(~/Users/[username]/Library/Keychains/login.keychain) : It has user id/password about installed application, ssh/vpn, mail, contacts, calendar and so on. It has key for call history decryption too.
* System Keychain(/Library/Keychains/System.keychain) : It has WiFi password registered by local machine and several certifications and public/private keys. (Detailed Info : http://forensic.n0fate.com/2014/09/system-keychain-analysis/)

## How to use:

If you have only keychain file and password, command as follow:

    $ python chainbreaker.py 
    usage: chainbreaker.py [-h] -f FILE (-k KEY | -p PASSWORD)
    chainbreaker.py: error: argument -f/--file is required


If you have memory image, you can extract master key candidates using volafox project. The volafox, memory forensic toolit for Mac OS X has been written in Python as a cross platform open source project. Of course, you can dump it using volatility.

    $ python volafox.py -i [memory image] -o keychaindump
    ....
    ....
    $ python chainbreaker.py -f [keychain file] -k [master key]


## Example
    $ python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump
    
    [+] Find MALLOC_TINY heap range (guess)
     [-] range 0x7fef03400000-0x7fef03500000
     [-] range 0x7fef03500000-0x7fef03600000
     [-] range 0x7fef03600000-0x7fef03700000
     [-] range 0x7fef04800000-0x7fef04900000
     [-] range 0x7fef04900000-0x7fef04a00000
    
    [*] Search for keys in range 0x7fef03400000-0x7fef03500000 complete. master key candidates : 0
    [*] Search for keys in range 0x7fef03500000-0x7fef03600000 complete. master key candidates : 0
    [*] Search for keys in range 0x7fef03600000-0x7fef03700000 complete. master key candidates : 0
    [*] Search for keys in range 0x7fef04800000-0x7fef04900000 complete. master key candidates : 0
    [*] Search for keys in range 0x7fef04900000-0x7fef04a00000 complete. master key candidates : 6
    
    [*] master key candidate: 78006A6CC504140E077D62D39F30DBBAFC5BDF5995039974
    [*] master key candidate: 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9
    [*] master key candidate: 2DD97A4ED361F492C01FFF84962307D7B82343B94595726E
    [*] master key candidate: 21BB87A2EB24FD663A0AC95E16BEEBF7728036994C0EEC19
    [*] master key candidate: 05556393141766259F62053793F62098D21176BAAA540927
    [*] master key candidate: 903C49F0FE0700C0133749F0FE0700404158544D00000000
    $ python chainbreaker.py -h
    usage: chainbreaker.py [-h] -f FILE (-k KEY | -p PASSWORD)
    
    Tool for OS X Keychain Analysis by @n0fate
    
    optional arguments:
      -h, --help            show this help message and exit
      -f FILE, --file FILE  Keychain file(*.keychain)
      -k KEY, --key KEY     Masterkey candidate
      -p PASSWORD, --password PASSWORD
                            User Password 
    $ python chainbreaker.py -f ~/Desktop/show/login.keychain -k 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9
     [-] DB Key
    00000000:  05 55 63 93 14 17 66 25  9F 62 05 37 93 F6 20 98  .Uc...f%.b.7.. .
    00000010:  D2 11 76 BA AA 54 09 27                                                   ..v..T.'
    [+] Symmetric Key Table: 0x00006488
    [+] Generic Password: 0x0000dea4
    [+] Generic Password Record
     [-] RecordSize : 0x000000fc
     [-] Record Number : 0x00000000
     [-] SECURE_STORAGE_GROUP(SSGP) Area : 0x0000004c
     [-] Create DateTime: 20130318062355Z
     [-] Last Modified DateTime: 20130318062355Z
     [-] Description : 
     [-] Creator : 
     [-] Type : 
     [-] PrintName : ***********@gmail.com
     [-] Alias : 
     [-] Account : 1688945386
     [-] Service : iCloud
     [-] Password
    00000000:  ** ** ** ** ** ** ** **  ** ** ** ** ** ** ** **  ****************
    00000010:  7A ** 69 ** 50 ** 51 36  ** ** ** 48 32 61 31 66  ****************
    00000020:  ** 49 ** 73 ** 62 ** 79  79 41 6F 3D              **********=
    
    <snip>
    
    [+] Internet Record
     [-] RecordSize : 0x0000014c
     [-] Record Number : 0x00000005
     [-] SECURE_STORAGE_GROUP(SSGP) Area : 0x0000002c
     [-] Create DateTime: 20130318065146Z
     [-] Last Modified DateTime: 20130318065146Z
     [-] Description : Web form password
     [-] Comment : default
     [-] Creator : 
     [-] Type : 
     [-] PrintName : www.facebook.com (***********@gmail.com)
     [-] Alias : 
     [-] Protected : 
     [-] Account : ***********@gmail.com
     [-] SecurityDomain : 
     [-] Server : www.facebook.com
     [-] Protocol Type : kSecProtocolTypeHTTPS
     [-] Auth Type : kSecAuthenticationTypeHTMLForm
     [-] Port : 0
     [-] Path : 
     [-] Password
    00000000:  ** ** ** ** ** ** ** **  ** ** ** **              ************

If you have memory image only, you can dump a keychain file on it and decrypt keychain contents as [link](https://gist.github.com/n0fate/790428d408d54b910956)


## Contacts
chainbreaker was written by [n0fate](http://twitter.com/n0fate)
E-Mail address can be found from source code.

## License
[GNU GPL v2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
