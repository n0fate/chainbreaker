chainbreaker
============

Chain Breaker is able to extract user credential in a Keychain file with Master Key or user password in forensically sound manner.

Master Key candidates can be extracted from volafox keychaindump module.

##Supported OS

Snow Leopard, Lion, Mountain Lion, Mavericks

##How to use:

### requirement : keychain file and user password

If you have only keychain file, command as follow:

### command

    # python chainbreaker.py -i [keychain file] -p [user password]



### requirement : keychain file and memory image

If you have memory image, you can extract master key candidates using volafox project.

The volafox, memory forensic toolit for Mac OS X has been written in Python as a cross platform open source project.

[volafox project - google code](http://code.google.com/p/volafox/)

### command

    $ python volafox.py -i [memory image] -o keychaindump
    ....
    ....
    $ python chainbreaker.py -i [keychain file] -k [master key]


## Example
    $ python vol.py -i ~/Desktop/show/macosxml.mem -o keychaindump
    
    [+] Virtual Memory Map Information
     [-] Virtual Address Start Point: 0x108240000
     [-] Virtual Address End Point: 0x7fffffe00000
     [-] Number of Entries: 85
    
    [+] Generating Process Virtual Memory Maps
     [-] Region from 0x108240000 to 0x108349000 (r-x, max rwx;)
     [-] Region from 0x108349000 to 0x108356000 (rw-, max rwx;)
     [-] Region from 0x108356000 to 0x108371000 (r--, max rwx;)
     [-] Region from 0x108371000 to 0x108372000 (r--, max rwx;)
     [-] Region from 0x108372000 to 0x108373000 (r--, max rwx;)
     [-] Region from 0x108373000 to 0x108374000 (rw-, max rwx;)
     [-] Region from 0x108374000 to 0x108375000 (r--, max rwx;)
     [-] Region from 0x108375000 to 0x108384000 (r-x, max rwx;)
     [-] Region from 0x108384000 to 0x108385000 (rw-, max rwx;)
     ... <snip> ...
     [-] Region from 0x108821000 to 0x108822000 (---, max rwx;)
     [-] Region from 0x108822000 to 0x108837000 (rw-, max rwx;)
     [-] Region from 0x108837000 to 0x108838000 (---, max rwx;)
     [-] Region from 0x108838000 to 0x108839000 (---, max rwx;)
     [-] Region from 0x108839000 to 0x10884e000 (rw-, max rwx;)
     [-] Region from 0x10884e000 to 0x10884f000 (---, max rwx;)
     [-] Region from 0x10884f000 to 0x1088aa000 (rw-, max rwx;)
     [-] Region from 0x1088aa000 to 0x109acf000 (r--, max r-x;)
     [-] Region from 0x7fef03400000 to 0x7fef03500000 (rw-, max rwx;)
     [-] Region from 0x7fef03500000 to 0x7fef03600000 (rw-, max rwx;)
     [-] Region from 0x7fef03600000 to 0x7fef03700000 (rw-, max rwx;)
     [-] Region from 0x7fef03800000 to 0x7fef04000000 (rw-, max rwx;)
     [-] Region from 0x7fef04000000 to 0x7fef04800000 (rw-, max rwx;)
     [-] Region from 0x7fef04800000 to 0x7fef04900000 (rw-, max rwx;)
     [-] Region from 0x7fef04900000 to 0x7fef04a00000 (rw-, max rwx;)
     ... <snip> ...
     [-] Region from 0x7fff80000000 to 0x7fffc0000000 (r--, max rwx;)
     [-] Region from 0x7fffc0000000 to 0x7fffffe00000 (r--, max rwx;)
     [-] Region from 0x7fffffe00000 to 0x7fffffe01000 (r--, max r--;)
     [-] Region from 0x7fffffe6e000 to 0x7fffffe6f000 (r-x, max r-x;)
    
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

    $ python chainbreaker.py -i ~/Desktop/show/login.keychain -k 26C80BE3346E720DAA10620F2C9C8AD726CFCE2B818942F9
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


## Contacts

chainbreaker was written by [n0fate](http://twitter.com/n0fate)

email address can be found from source code.

## License
[GNU GPL v2](http://www.gnu.org/licenses/old-licenses/gpl-2.0.html)
