#!/usr/bin/python

# Author : n0fate
# E-Mail rapfer@gmail.com, n0fate@n0fate.com
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 2 of the License, or (at
# your option) any later version.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
# General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
#

import getopt
from sys import argv, exit, stdout, stdin, stderr
import struct
from binascii import hexlify, unhexlify
import datetime

from pbkdf2 import pbkdf2

from pyDes import triple_des, CBC

ATOM_SIZE = 4

KEYCHAIN_SIGNATURE = unhexlify('6b796368')

DBBLOB_SIGNATURE = unhexlify('fade0711')

BLOCKSIZE = 8
KEYLEN = 24

# struct APPLE_DB_HEADER {
# char signature[4]; // 'kych'
# uint version; // 0x10000
# uint headersize; // 0x10
# uint schemaoffset; // 0x14
# uint authoffset; // 0x00
# }
APPL_DB_HEADER = '>4sIIII'
APPL_DB_HEADER_SIZE = 20

#struct APPLE_DB_SCHEMA {
#    uint schemasize;
#    uint tablecount;
#    tablelist;
#}
APPL_DB_SCHEMA = '>II'
APPL_DB_SCHEMA_SIZE = 8


#struct RECORD {
#   uint RecordSize;
#   uint RecordCount;
#
#
#
#
#
#
#   uint RECORD_TYPE;   // RECORD
#   uint datalength
#   char data[datalength]
#}


KEY_BLOB_RECORD_HEADER = '>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII'
KEY_BLOB_RECORD = '>IIII'


#struct GENERIC_PW_HEADER {
#    uint recordsize; # record size (dbblob header + dbblob)
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint createtime_ptr; # key create time
#    uint modifiedtime_ptr; # key modified time
#    uint unknown;
#    uint unknown;
#    uint name_ptr; # key name
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint account_ptr; # Account
#    uint path_ptr; # Application Path
#}

GENERIC_PW_HEADER = '>IIIIIIIIIIIIIIIIIIIIII'

#struct INTERNET_PW_HEADER {
#    uint recordsize; # record size (dbblob header + dbblob)
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint createtime_ptr; # key create time
#    uint modifiedtime_ptr; # key modified time
#    uint unknown;
#    uint unknown;
#    uint name_ptr; # key name
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint account_ptr; # Account
#    uint path_ptr; # Application Path
#    uint name2_ptr;
#    uint protocol;
#    uint authtype;
#    uint where;
#}
INTERNET_PW_HEADER = '>IIIIIIIIIIIIIIIIIIIIIIIIII'

#struct TABLE_HEADER {
#    uint tablesize;
#    uint tableid;
#    uint recordcount;
#    uint records;
#    uint indexesoffset;
#    uint freelisthead;
#    uint recordnumberscount;
#    uint recordnumbers;
#}
TABLE_HEADER = ">IIIIIII"

#struct SCHEMA_INFO_RECORD {
#    uint recordsize;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint unknown;
#    uint recordtype;
#    uint datasize;
#    uint data;
#}
SCHEMA_INFO_RECORD = '>IIIIIIIIII'

#CSSM TYPE
## http://www.opensource.apple.com/source/libsecurity_cssm/libsecurity_cssm-36064/lib/cssmtype.h

########## CSSM_DB_RECORDTYPE #############

#/* Industry At Large Application Name Space Range Definition */
#/* AppleFileDL record types. */
CSSM_DB_RECORDTYPE_APP_DEFINED_START = 0x80000000
CSSM_DL_DB_RECORD_GENERIC_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0
CSSM_DL_DB_RECORD_INTERNET_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 1
CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 2
CSSM_DL_DB_RECORD_USER_TRUST = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 3
CSSM_DL_DB_RECORD_X509_CRL = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 4
CSSM_DL_DB_RECORD_UNLOCK_REFERRAL = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 5
CSSM_DL_DB_RECORD_EXTENDED_ATTRIBUTE = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 6

CSSM_DL_DB_RECORD_X509_CERTIFICATE = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0x1000
CSSM_DL_DB_RECORD_METADATA = CSSM_DB_RECORDTYPE_APP_DEFINED_START + 0x8000  ## DBBlob
CSSM_DB_RECORDTYPE_APP_DEFINED_END = 0xffffffff

#/* Record Types defined in the Schema Management Name Space */
CSSM_DB_RECORDTYPE_SCHEMA_START = 0x00000000
CSSM_DL_DB_SCHEMA_INFO = CSSM_DB_RECORDTYPE_SCHEMA_START + 0
CSSM_DL_DB_SCHEMA_INDEXES = CSSM_DB_RECORDTYPE_SCHEMA_START + 1
CSSM_DL_DB_SCHEMA_ATTRIBUTES = CSSM_DB_RECORDTYPE_SCHEMA_START + 2
CSSM_DL_DB_SCHEMA_PARSING_MODULE = CSSM_DB_RECORDTYPE_SCHEMA_START + 3
CSSM_DB_RECORDTYPE_SCHEMA_END = CSSM_DB_RECORDTYPE_SCHEMA_START + 4

#/* Record Types defined in the Open Group Application Name Space */
#/* Open Group Application Name Space Range Definition*/
CSSM_DB_RECORDTYPE_OPEN_GROUP_START = 0x0000000A
CSSM_DL_DB_RECORD_ANY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 0
CSSM_DL_DB_RECORD_CERT = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 1
CSSM_DL_DB_RECORD_CRL = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 2
CSSM_DL_DB_RECORD_POLICY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 3
CSSM_DL_DB_RECORD_GENERIC = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 4
CSSM_DL_DB_RECORD_PUBLIC_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 5
CSSM_DL_DB_RECORD_PRIVATE_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 6
CSSM_DL_DB_RECORD_SYMMETRIC_KEY = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 7
CSSM_DL_DB_RECORD_ALL_KEYS = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 8
CSSM_DB_RECORDTYPE_OPEN_GROUP_END = CSSM_DB_RECORDTYPE_OPEN_GROUP_START + 8
#####################

######## KEYUSE #########
CSSM_KEYUSE_ANY = 0x80000000
CSSM_KEYUSE_ENCRYPT = 0x00000001
CSSM_KEYUSE_DECRYPT = 0x00000002
CSSM_KEYUSE_SIGN = 0x00000004
CSSM_KEYUSE_VERIFY = 0x00000008
CSSM_KEYUSE_SIGN_RECOVER = 0x00000010
CSSM_KEYUSE_VERIFY_RECOVER = 0x00000020
CSSM_KEYUSE_WRAP = 0x00000040
CSSM_KEYUSE_UNWRAP = 0x00000080
CSSM_KEYUSE_DERIVE = 0x00000100
####################


SECURE_STORAGE_GROUP = 'ssgp'

AUTH_TYPE = {
    'ntlm': 'kSecAuthenticationTypeNTLM',
    'msna': 'kSecAuthenticationTypeMSN',
    'dpaa': 'kSecAuthenticationTypeDPA',
    'rpaa': 'kSecAuthenticationTypeRPA',
    'http': 'kSecAuthenticationTypeHTTPBasic',
    'httd': 'kSecAuthenticationTypeHTTPDigest',
    'form': 'kSecAuthenticationTypeHTMLForm',
    'dflt': 'kSecAuthenticationTypeDefault',
    '': 'kSecAuthenticationTypeAny',
    '\x00\x00\x00\x00': 'kSecAuthenticationTypeAny'
}

PROTOCOL_TYPE = {
    'ftp ': 'kSecProtocolTypeFTP',
    'ftpa': 'kSecProtocolTypeFTPAccount',
    'http': 'kSecProtocolTypeHTTP',
    'irc ': 'kSecProtocolTypeIRC',
    'nntp': 'kSecProtocolTypeNNTP',
    'pop3': 'kSecProtocolTypePOP3',
    'smtp': 'kSecProtocolTypeSMTP',
    'sox ': 'kSecProtocolTypeSOCKS',
    'imap': 'kSecProtocolTypeIMAP',
    'ldap': 'kSecProtocolTypeLDAP',
    'atlk': 'kSecProtocolTypeAppleTalk',
    'afp ': 'kSecProtocolTypeAFP',
    'teln': 'kSecProtocolTypeTelnet',
    'ssh ': 'kSecProtocolTypeSSH',
    'ftps': 'kSecProtocolTypeFTPS',
    'htps': 'kSecProtocolTypeHTTPS',
    'htpx': 'kSecProtocolTypeHTTPProxy',
    'htsx': 'kSecProtocolTypeHTTPSProxy',
    'ftpx': 'kSecProtocolTypeFTPProxy',
    'cifs': 'kSecProtocolTypeCIFS',
    'smb ': 'kSecProtocolTypeSMB',
    'rtsp': 'kSecProtocolTypeRTSP',
    'rtsx': 'kSecProtocolTypeRTSPProxy',
    'daap': 'kSecProtocolTypeDAAP',
    'eppc': 'kSecProtocolTypeEPPC',
    'ipp ': 'kSecProtocolTypeIPP',
    'ntps': 'kSecProtocolTypeNNTPS',
    'ldps': 'kSecProtocolTypeLDAPS',
    'tels': 'kSecProtocolTypeTelnetS',
    'imps': 'kSecProtocolTypeIMAPS',
    'ircs': 'kSecProtocolTypeIRCS',
    'pops': 'kSecProtocolTypePOP3S',
    'cvsp': 'kSecProtocolTypeCVSpserver',
    'svn ': 'kSecProtocolTypeCVSpserver',
    'AdIM': 'kSecProtocolTypeAdiumMessenger',
    '\x00\x00\x00\x00': 'kSecProtocolTypeAny'
}

# This is somewhat gross: we define a bunch of module-level constants based on
# the SecKeychainItem.h defines (FourCharCodes) by passing them through
# struct.unpack and converting them to ctypes.c_long() since we'll never use
# them for non-native APIs

CARBON_DEFINES = {
    'cdat': 'kSecCreationDateItemAttr',
    'mdat': 'kSecModDateItemAttr',
    'desc': 'kSecDescriptionItemAttr',
    'icmt': 'kSecCommentItemAttr',
    'crtr': 'kSecCreatorItemAttr',
    'type': 'kSecTypeItemAttr',
    'scrp': 'kSecScriptCodeItemAttr',
    'labl': 'kSecLabelItemAttr',
    'invi': 'kSecInvisibleItemAttr',
    'nega': 'kSecNegativeItemAttr',
    'cusi': 'kSecCustomIconItemAttr',
    'acct': 'kSecAccountItemAttr',
    'svce': 'kSecServiceItemAttr',
    'gena': 'kSecGenericItemAttr',
    'sdmn': 'kSecSecurityDomainItemAttr',
    'srvr': 'kSecServerItemAttr',
    'atyp': 'kSecAuthenticationTypeItemAttr',
    'port': 'kSecPortItemAttr',
    'path': 'kSecPathItemAttr',
    'vlme': 'kSecVolumeItemAttr',
    'addr': 'kSecAddressItemAttr',
    'ssig': 'kSecSignatureItemAttr',
    'ptcl': 'kSecProtocolItemAttr',
    'ctyp': 'kSecCertificateType',
    'cenc': 'kSecCertificateEncoding',
    'crtp': 'kSecCrlType',
    'crnc': 'kSecCrlEncoding',
    'alis': 'kSecAlias',
    'inet': 'kSecInternetPasswordItemClass',
    'genp': 'kSecGenericPasswordItemClass',
    'ashp': 'kSecAppleSharePasswordItemClass',
    CSSM_DL_DB_RECORD_X509_CERTIFICATE: 'kSecCertificateItemClass'
}

############################ SOURCE END ###################################

class KeyChain():
    def __init__(self, filepath):
        self.filepath = filepath
        self.fhandle = ''
        self.fbuf = ''

    def open(self):
        try:
            self.fhandle = open(self.filepath, 'rb')
        except:
            return 1
        self.fbuf = self.fhandle.read()
        return self.fbuf

    def close(self):
        #close(self.fhandle)
        return

    ## get apple DB Header
    def get_header(self, fbuf, offset):
        if fbuf == '':
            return 1, []

        header = struct.unpack(APPL_DB_HEADER, fbuf[offset:offset + APPL_DB_HEADER_SIZE])

        return 0, header

    def get_schema_info(self, fbuf, offset):

        table_list = []

        schema_info = struct.unpack(APPL_DB_SCHEMA, fbuf[offset:offset + APPL_DB_SCHEMA_SIZE])

        TableCount = schema_info[1]

        for i in range(0, TableCount):
            BASE_ADDR = (APPL_DB_HEADER_SIZE) + (APPL_DB_SCHEMA_SIZE)
            table_list.append(
                struct.unpack('>I', fbuf[BASE_ADDR + (ATOM_SIZE * i):BASE_ADDR + (ATOM_SIZE * i) + ATOM_SIZE])[0])

        return schema_info, table_list

    def get_table(self, fbuf, offset):

        # get table list
        record_list = []
        BASE_ADDR = APPL_DB_HEADER_SIZE + offset

        table_meta = struct.unpack(TABLE_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 16 + 12])

        RECORD_OFFSET_BASE = BASE_ADDR + 16 + 12

        #print 'record offset: %x'%RECORD_OFFSET_BASE

        # print '[+] Table'
        # print ' [-] Size : 0x%.8x'%table_meta[0]
        # print ' [-] ID : 0x%.8x'%table_meta[1]
        # print ' [-] Records Count : 0x%.8x'%table_meta[2]
        # print ' [-] Records : 0x%.8x'%table_meta[3]
        # print ' [-] Indexes Offset : 0x%.8x'%table_meta[4]
        # print ' [-] FreeListHead : 0x%.8x'%table_meta[5]
        # print ' [-] RecordNumbers Count : 0x%.8x'%table_meta[6]

        record_count = 0
        offset = 0
        while table_meta[2] != record_count:
            record_offset = struct.unpack('>I', fbuf[
                                                RECORD_OFFSET_BASE + (ATOM_SIZE * offset):RECORD_OFFSET_BASE + (
                                                    ATOM_SIZE * offset) + ATOM_SIZE])[0]
            # if len(record_list) >= 1:
            #     if record_list[len(record_list)-1] >= record_offset:
            #         continue
            if (record_offset != 0x00) and (record_offset%4 == 0):
                record_list.append(record_offset)
                #print ' [-] Record Offset: 0x%.8x'%record_offset
                record_count += 1
            offset +=1

        return table_meta, record_list

    def getTablenametoList(self, recordList, tableList):
        TableDic = {}
        for count in range(0, len(recordList)):
            tableMeta, GenericList = self.get_table(self.fbuf, tableList[count])
            TableDic[tableMeta[1]] = count    # extract valid table list

        return len(recordList), TableDic

    def get_schema_info_record(self, fbuf, base_addr, offset):

        record_meta = []
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        record_meta = struct.unpack(SCHEMA_INFO_RECORD, fbuf[BASE_ADDR:BASE_ADDR + 40])

        datasize = record_meta[9]  # datasize

        data = fbuf[BASE_ADDR + 40:BASE_ADDR + 40 + datasize]

        for record_element in record_meta:
            record.append(record_element)

        record.append(data)

        return record

    def get_keyblob_record(self, fbuf, base_addr, offset):
        record_meta = []
        #record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        record_meta = struct.unpack(KEY_BLOB_RECORD_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 0x84])

        # sorting record data
        #for record_element in record_meta:
        #    record.append(record_element)

        # record_meta[0] => record size
        record_buf = fbuf[BASE_ADDR + 0x84:BASE_ADDR + record_meta[0]]  # password data area

        pw_data = struct.unpack(KEY_BLOB_RECORD, record_buf[:16])
        signature = pw_data[0]
        version = pw_data[1]
        cipheroff = pw_data[2]
        totallen = pw_data[3]

        if SECURE_STORAGE_GROUP != str(record_buf[totallen + 8:totallen + 8 + 4]):
            #print 'not ssgp'
            return '', '', '', 1

        #print str(fbuf[BASE_ADDR+totallen+8:BASE_ADDR+totallen+8+4])

        cipherlen = totallen - cipheroff
        if cipherlen % BLOCKSIZE != 0:
            print "Bad ciphertext len"

        iv = record_buf[16:24]

        ciphertext = record_buf[cipheroff:totallen]

        # match data, keyblob_ciphertext, Initial Vector, success
        return record_buf[totallen + 8:totallen + 8 + 20], ciphertext, iv, 0


    def get_genericpw_record(self, fbuf, base_addr, offset):

        record_meta = []
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        record_meta = struct.unpack(GENERIC_PW_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 0x58])

        # sorting record data
        for record_element in record_meta:
            record.append(record_element)

        record_buf = fbuf[BASE_ADDR + 0x58:BASE_ADDR + record_meta[0]]  # record_meta[0] => record size

        # get SECURE_STORAGE_GROUP(ssgp) data area
        ssgp_area = record_meta[4]  # get ssgp_area (dynamic)

        if ssgp_area != 0:
            ssgp_data = record_buf[:ssgp_area]
            record.append(ssgp_data)
        else:
            record.append('')


        # get data pointer
        createtime_ptr = record_meta[6] - 1  # TIME_DATE
        modifiedtime_ptr = record_meta[7] - 1  # TIME_DATE
        description_ptr = record_meta[8] - 1  # BLOB
        comment_ptr = record_meta[9] - 1  # BLOB
        creator_ptr = record_meta[10] - 1  # uint32
        type_ptr = record_meta[11] - 1  # uint32
        scriptcode_ptr = record_meta[12] - 1  # sint32
        printname_ptr = record_meta[13] - 1  # BLOB
        alias_ptr = record_meta[14] - 1  # BLOB
        invisible_ptr = record_meta[15] - 1  # sint32
        negative_ptr = record_meta[16] - 1  # sint32
        customicon_ptr = record_meta[17] - 1  # sint32
        protected_ptr = record_meta[18] - 1  # BLOB
        account_ptr = record_meta[19] - 1  # BLOB
        service_ptr = record_meta[20] - 1  # BLOB


        # get create/last modified time (16byte * 2)
        if createtime_ptr != -1:
            createtime = struct.unpack('>16s', fbuf[BASE_ADDR + createtime_ptr:BASE_ADDR + createtime_ptr + 16])[0]
            record.append(createtime)
        else:
            record.append('')

        if modifiedtime_ptr != -1:
            modifiedtime = struct.unpack('>16s', fbuf[BASE_ADDR + modifiedtime_ptr:BASE_ADDR + modifiedtime_ptr + 16])[
                0]
            record.append(modifiedtime)
        else:
            record.append('')

        # decription
        if description_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + description_ptr:BASE_ADDR + description_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + description_ptr + 4:BASE_ADDR + description_ptr + 4 + real_str_len])[
                0]
            record.append(data)
        else:
            record.append('')

            # get account type kSecCreatorItemAttr
        if creator_ptr != -1:
            data_type = struct.unpack('>4s', fbuf[BASE_ADDR + creator_ptr:BASE_ADDR + creator_ptr + 4])[0]
            record.append(data_type)
        else:
            record.append('')

        # get account type kSecTypeItemAttr
        if type_ptr != -1:
            data = struct.unpack('>4s', fbuf[BASE_ADDR + type_ptr:BASE_ADDR + type_ptr + 4])[0]
            record.append(data)
        else:
            record.append('')

            # get name,account,path (LENGTH:VALUE) kSecLabelItemAttr
        if printname_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + printname_ptr:BASE_ADDR + printname_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            name = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + printname_ptr + 4:BASE_ADDR + printname_ptr + 4 + real_str_len])[0]
            record.append(name)
        else:
            record.append('')

        # get name,account,path (LENGTH:VALUE) kSecAlias
        if alias_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + alias_ptr:BASE_ADDR + alias_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + alias_ptr + 4:BASE_ADDR + alias_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if account_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + account_ptr:BASE_ADDR + account_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            account = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + account_ptr + 4:BASE_ADDR + account_ptr + 4 + real_str_len])[0]
            record.append(account)
        else:
            record.append('')

        if service_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + service_ptr:BASE_ADDR + service_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            path = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + service_ptr + 4:BASE_ADDR + service_ptr + 4 + real_str_len])[0]
            record.append(path)
        else:
            record.append('')

        return record

    def get_internetpw_record(self, fbuf, base_addr, offset):

        record_meta = []
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        record_meta = struct.unpack(INTERNET_PW_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 0x68])

        # sorting record data
        for record_element in record_meta:
            record.append(record_element)

        record_buf = fbuf[BASE_ADDR + 0x68:BASE_ADDR + record_meta[0]]  # record_meta[0] => record size

        # get SECURE_STORAGE_GROUP(ssgp) data area
        ssgp_area = record_meta[4]  # get ssgp_area (dynamic)

        if ssgp_area != 0:
            ssgp_data = record_buf[:ssgp_area]
            record.append(ssgp_data)
        else:
            record.append('')


        # get data pointer
        createtime_ptr = record_meta[6] - 1
        modifiedtime_ptr = record_meta[7] - 1
        description_ptr = record_meta[8] - 1
        comment_ptr = record_meta[9] - 1
        creator_ptr = record_meta[10] - 1
        type_ptr = record_meta[11] - 1
        scriptcode_ptr = record_meta[12] - 1
        printname_ptr = record_meta[13] - 1
        alias_ptr = record_meta[14] - 1
        invisible_ptr = record_meta[15] - 1
        negative_ptr = record_meta[16] - 1
        customicon_ptr = record_meta[17] - 1
        protected_ptr = record_meta[18] - 1
        account_ptr = record_meta[19] - 1
        securitydomain_ptr = record_meta[20] - 1
        server_ptr = record_meta[21] - 1
        protocol_ptr = record_meta[22] - 1
        authtype_ptr = record_meta[23] - 1
        port_ptr = record_meta[24] - 1
        path_ptr = record_meta[25] - 1


        # get create/last modified time (16byte * 2)
        if createtime_ptr != -1:
            createtime = struct.unpack('>16s', fbuf[BASE_ADDR + createtime_ptr:BASE_ADDR + createtime_ptr + 16])[0]
            record.append(createtime)
        else:
            record.append('')

        if modifiedtime_ptr != -1:
            modifiedtime = struct.unpack('>16s', fbuf[BASE_ADDR + modifiedtime_ptr:BASE_ADDR + modifiedtime_ptr + 16])[
                0]
            record.append(modifiedtime)
        else:
            record.append('')

        # get name,account,path (LENGTH:VALUE)
        if description_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + description_ptr:BASE_ADDR + description_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + description_ptr + 4:BASE_ADDR + description_ptr + 4 + real_str_len])[
                0]
            record.append(data)
        else:
            record.append('')

        # get name,account,path (LENGTH:VALUE)
        if comment_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + comment_ptr:BASE_ADDR + comment_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + comment_ptr + 4:BASE_ADDR + comment_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        # get creator type
        if creator_ptr != -1:
            data = struct.unpack('>4s', fbuf[BASE_ADDR + creator_ptr:BASE_ADDR + creator_ptr + 4])[0]
            record.append(data)
        else:
            record.append('')

        # get account type
        if type_ptr != -1:
            data_type = struct.unpack('>4s', fbuf[BASE_ADDR + type_ptr:BASE_ADDR + type_ptr + 4])[0]
            record.append(data_type)
        else:
            record.append('')


        # get name,account,path (LENGTH:VALUE)
        if printname_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + printname_ptr:BASE_ADDR + printname_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + printname_ptr + 4:BASE_ADDR + printname_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if alias_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + alias_ptr:BASE_ADDR + alias_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + alias_ptr + 4:BASE_ADDR + alias_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if protected_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + protected_ptr:BASE_ADDR + protected_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + protected_ptr + 4:BASE_ADDR + protected_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if account_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + account_ptr:BASE_ADDR + account_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            account = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + account_ptr + 4:BASE_ADDR + account_ptr + 4 + real_str_len])[0]
            record.append(account)
        else:
            record.append('')

        if securitydomain_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + securitydomain_ptr:BASE_ADDR + securitydomain_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value, fbuf[
                                               BASE_ADDR + securitydomain_ptr + 4:BASE_ADDR + securitydomain_ptr + 4 + real_str_len])[
                0]
            record.append(data)
        else:
            record.append('')

        if server_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + server_ptr:BASE_ADDR + server_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + server_ptr + 4:BASE_ADDR + server_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if protocol_ptr != -1:
            protocol = struct.unpack('>4s', fbuf[BASE_ADDR + protocol_ptr:BASE_ADDR + protocol_ptr + 4])[0]
            record.append(protocol)
        else:
            record.append('')

        if authtype_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + authtype_ptr:BASE_ADDR + authtype_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            authtype = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + authtype_ptr + 4:BASE_ADDR + authtype_ptr + 4 + real_str_len])[
                    0]
            record.append(authtype)
        else:
            record.append('')

        if port_ptr != -1:
            data = struct.unpack('>I', fbuf[BASE_ADDR + port_ptr:BASE_ADDR + port_ptr + 4])[0]
            record.append(data)
        else:
            record.append('')

        #print 'where ptr 0x%.8x'%where_ptr
        if path_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + path_ptr:BASE_ADDR + path_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            where = struct.unpack(unpack_value, fbuf[BASE_ADDR + path_ptr + 4:BASE_ADDR + path_ptr + 4 + real_str_len])[
                0]
            record.append(where)
        else:
            record.append('')

        return record

    def get_appleshare_record(self, fbuf, base_addr, offset):

        record_meta = []
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        record_meta = struct.unpack(INTERNET_PW_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 0x68])

        # sorting record data
        for record_element in record_meta:
            record.append(record_element)

        record_buf = fbuf[BASE_ADDR + 0x64:BASE_ADDR + record_meta[0]]  # record_meta[0] => record size

        # get SECURE_STORAGE_GROUP(ssgp) data area
        ssgp_area = record_meta[4]  # get ssgp_area (dynamic)

        if ssgp_area != 0:
            ssgp_data = record_buf[:ssgp_area]
            record.append(ssgp_data)
        else:
            record.append('')


        # get data pointer
        createtime_ptr = record_meta[6] - 1
        modifiedtime_ptr = record_meta[7] - 1
        description_ptr = record_meta[8] - 1
        comment_ptr = record_meta[9] - 1
        creator_ptr = record_meta[10] - 1
        type_ptr = record_meta[11] - 1
        scriptcode_ptr = record_meta[12] - 1
        printname_ptr = record_meta[13] - 1
        alias_ptr = record_meta[14] - 1
        invisible_ptr = record_meta[15] - 1
        negative_ptr = record_meta[16] - 1
        customicon_ptr = record_meta[17] - 1
        protected_ptr = record_meta[18] - 1
        account_ptr = record_meta[19] - 1
        volume_ptr = record_meta[20] - 1
        server_ptr = record_meta[21] - 1
        protocol_ptr = record_meta[22] - 1
        address_ptr = record_meta[23] - 1
        signature_ptr = record_meta[24] - 1


        # get create/last modified time (16byte * 2)
        if createtime_ptr != -1:
            createtime = struct.unpack('>16s', fbuf[BASE_ADDR + createtime_ptr:BASE_ADDR + createtime_ptr + 16])[0]
            record.append(createtime)
        else:
            record.append('')

        if modifiedtime_ptr != -1:
            modifiedtime = struct.unpack('>16s', fbuf[BASE_ADDR + modifiedtime_ptr:BASE_ADDR + modifiedtime_ptr + 16])[
                0]
            record.append(modifiedtime)
        else:
            record.append('')

        # get name,account,path (LENGTH:VALUE)
        if description_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + description_ptr:BASE_ADDR + description_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + description_ptr + 4:BASE_ADDR + description_ptr + 4 + real_str_len])[
                0]
            record.append(data)
        else:
            record.append('')

        # get name,account,path (LENGTH:VALUE)
        if comment_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + comment_ptr:BASE_ADDR + comment_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + comment_ptr + 4:BASE_ADDR + comment_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        # get creator type
        if creator_ptr != -1:
            data = struct.unpack('>4s', fbuf[BASE_ADDR + creator_ptr:BASE_ADDR + creator_ptr + 4])[0]
            record.append(data)
        else:
            record.append('')

        # get account type
        if type_ptr != -1:
            data_type = struct.unpack('>4s', fbuf[BASE_ADDR + type_ptr:BASE_ADDR + type_ptr + 4])[0]
            record.append(data_type)
        else:
            record.append('')


        # get name,account,path (LENGTH:VALUE)
        if printname_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + printname_ptr:BASE_ADDR + printname_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + printname_ptr + 4:BASE_ADDR + printname_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if alias_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + alias_ptr:BASE_ADDR + alias_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + alias_ptr + 4:BASE_ADDR + alias_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if protected_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + protected_ptr:BASE_ADDR + protected_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + protected_ptr + 4:BASE_ADDR + protected_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if account_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + account_ptr:BASE_ADDR + account_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            account = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + account_ptr + 4:BASE_ADDR + account_ptr + 4 + real_str_len])[0]
            record.append(account)
        else:
            record.append('')

        if volume_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + volume_ptr:BASE_ADDR + volume_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + volume_ptr + 4:BASE_ADDR + volume_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if server_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + server_ptr:BASE_ADDR + server_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + server_ptr + 4:BASE_ADDR + server_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        if protocol_ptr != -1:
            protocol = struct.unpack('>4s', fbuf[BASE_ADDR + protocol_ptr:BASE_ADDR + protocol_ptr + 4])[0]
            record.append(protocol)
        else:
            record.append('')

        #print 'where ptr 0x%.8x'%where_ptr
        if address_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + address_ptr:BASE_ADDR + address_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = \
                struct.unpack(unpack_value, fbuf[BASE_ADDR + address_ptr + 4:BASE_ADDR + address_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        #print 'where ptr 0x%.8x'%where_ptr
        if signature_ptr != -1:
            str_length = struct.unpack('>I', fbuf[BASE_ADDR + signature_ptr:BASE_ADDR + signature_ptr + 4])[0]

            # 4byte arrangement
            if (str_length % 4) == 0:
                real_str_len = (str_length / 4) * 4
            else:
                real_str_len = ((str_length / 4) + 1) * 4
            unpack_value = '>' + str(real_str_len) + 's'

            data = struct.unpack(unpack_value,
                                 fbuf[BASE_ADDR + signature_ptr + 4:BASE_ADDR + signature_ptr + 4 + real_str_len])[0]
            record.append(data)
        else:
            record.append('')

        return record

    ## decrypted dbblob area
    ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    ## http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-36620/lib/StorageManager.cpp
    def decrypted_db_blob(self, securestoragegroup, dbkey):
        iv = securestoragegroup[20:28]

        #print 'IV'
        #hexdump(iv)

        plain = kcdecrypt(dbkey, iv, securestoragegroup[28:])

        #hexdump(plain)

        return plain

    # Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    # source : http://www.opensource.apple.com/source/libsecurity_cdsa_client/libsecurity_cdsa_client-36213/lib/securestorage.cpp
    # magicCmsIV : http://www.opensource.apple.com/source/Security/Security-28/AppleCSP/AppleCSP/wrapKeyCms.cpp
    def decrypted_keyblob(self, encryptedblob, iv, dbkey):

        magicCmsIV = unhexlify('4adda22c79e82105')
        #cipheroff = struct.unpack('>I', encryptedblob[8:12])
        plain = kcdecrypt(dbkey, magicCmsIV, encryptedblob)

        if plain.__len__() == 0:
            return ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(32):
            revplain += plain[31 - i]

        # now the real key gets found. */
        plain = kcdecrypt(dbkey, iv, revplain)

        keyblob = plain[4:]

        if len(keyblob) != KEYLEN:
            #raise "Bad decrypted keylen!"
            return ''

        return keyblob

    ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    def generate_master_key(self, pw, fbuf, symmetrickey_offset):

        base_addr = APPL_DB_HEADER_SIZE + symmetrickey_offset + 0x38  # header

        # salt
        SALTLEN = 20
        salt = fbuf[base_addr + 44:base_addr + 44 + SALTLEN]

        master = pbkdf2(pw, salt, 1000, KEYLEN)

        #print ' [-] Master Key'
        #hexdump(master)

        return master

    ## find DBBlob and extract Wrapping key
    def find_wrapping_key(self, master, fbuf, symmetrickey_offset):

        base_addr = APPL_DB_HEADER_SIZE + symmetrickey_offset + 0x38

        # startCryptoBlob
        cipher_text_offset = struct.unpack('>I', fbuf[base_addr + 8:base_addr + 8 + ATOM_SIZE])[0]

        # totalength
        totallength = struct.unpack('>I', fbuf[base_addr + 12:base_addr + 12 + ATOM_SIZE])[0]

        # IV
        IVLEN = 8
        iv = fbuf[base_addr + 64:base_addr + 64 + IVLEN]

        #print ' [-] IV'
        #hexdump(iv)

        # get cipher text area
        ciphertext = fbuf[base_addr + cipher_text_offset:base_addr + totallength]

        #print ' [-] CipherText'
        #hexdump(ciphertext)

        # decrypt the key
        plain = kcdecrypt(master, iv, ciphertext)

        if plain.__len__() == 0:
            return ''

        dbkey = plain[0:KEYLEN]

        # return encrypted wrapping key

        return dbkey

    def getdatetime(self, datestring):
        return datetime.datetime.strptime(datestring[:-2], '%Y%m%d%H%M%S')  # remove 'Z' and '\x00'


# SOURCE : extractkeychain.py
def kcdecrypt(key, iv, data):
    if len(data) == 0:
        #print>>stderr, "FileSize is 0"
        return data

    if len(data) % BLOCKSIZE != 0:
        return data

    cipher = triple_des(key, CBC, iv)
    # the line below is for pycrypto instead
    #cipher = DES3.new( key, DES3.MODE_CBC, iv )

    plain = cipher.decrypt(data)

    #print ' [-] Plain'
    #hexdump(plain)

    # now check padding
    pad = ord(plain[-1])
    if pad > 8:
        #print>> stderr, "Bad padding byte. You probably have a wrong password"
        return ''

    for z in plain[-pad:]:
        if ord(z) != pad:
            #print>> stderr, "Bad padding. You probably have a wrong password"
            return ''

    plain = plain[:-pad]

    return plain


# SOURCE: http://mwultong.blogspot.com/2007/04/python-hex-viewer-file-dumper.html
def hexdump(buf):
    offset = 0
    while offset < len(buf):
        buf16 = buf[offset:offset + 16]
        buf16Len = len(buf16)
        if buf16Len == 0: break
        output = "%08X:  " % (offset)

        for i in range(buf16Len):
            if (i == 8): output += " "
            output += "%02X " % (ord(buf16[i]))

        for i in range(((16 - buf16Len) * 3) + 1):
            output += " "
            if (buf16Len < 9):
                output += " "

        for i in range(buf16Len):
            if (ord(buf16[i]) >= 0x20 and ord(buf16[i]) <= 0x7E):
                output += buf16[i]
            else:
                output += "."

        offset += 16
        print output

    if (offset == 0):
        print "%08X:  " % (offset)


def usage():
    print 'python chainbreaker.py [-i USER KEYCHAIN] [-k MASTER KEY or -p PASSWORD]'


def main():
    password = ''
    masterkey = ''
    keychain_file = ''

    try:
        option, args = getopt.getopt(argv[1:], 'i:p:k:')

    except getopt.GetoptError, err:
        usage(argv)
        exit()

    #print option
    for op, p, in option:
        if op in '-i':
            keychain_file = p
        elif op in '-p':
            password = p
        elif op in '-k':
            masterkey = p
        else:
            print 'invalid option'
            exit()

    try:
        if keychain_file == '' and (password == '' or masterkey == ''):
            usage()
            exit()

    except IndexError:
        usage()
        exit()

    try:
        f = open(keychain_file, 'rb')
    except IOError:
        print '[+] WARNING!! Can not open keychain.'
        #usage(sys.argv)
        exit()

    fbuf = ''

    keychain = KeyChain(keychain_file)
    fbuf = keychain.open()
    if '' == fbuf:
        print '[+] Open Failed'
        exit()

    keychain.close()

    keychain_header = []

    bRet, keychain_header = keychain.get_header(fbuf, 0)
    #print '[+] KeyChain Header'
    #print ' [-] Signature : %s'%keychain_header[0]
    #print ' [-] Version : 0x%.8x'%keychain_header[1]
    #print ' [-] Unknown : 0x%.8x'%keychain_header[2]
    #print ' [-] SchemaOffset : 0x%.8x'%keychain_header[3]

    if keychain_header[0] != KEYCHAIN_SIGNATURE:
        print 'Invalid Keychain Format'
        exit()

    schema_info, table_list = keychain.get_schema_info(fbuf, keychain_header[3])
    #print '[+] Schema Info'
    #print ' [-] Schema Size : 0x%.8x'%schema_info[0]
    #print ' [-] Table Count : 0x%.8x'%schema_info[1]
    #for table_offset in table_list:
    #    print ' [-] Table Offset: 0x%.8x'%table_offset

    table_meta, record_list = keychain.get_table(fbuf, table_list[0])
    #
    #record_offset = record_list[0]
    #tempcount = 0
    #record = keychain.get_schema_info_record(fbuf, table_list[0], record_offset)
    #for record_offset in record_list:
    #    record = keychain.get_schema_info_record(fbuf, table_list[0], record_offset)
    #    print '[+] Record : 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[tempcount])
    #    print ' [-] RecordSize : 0x%.8x'%record[0]
    #    print ' [-] Record Number : 0x%.8x'%record[1]
    #    print ' [-] Unknown1 : 0x%.8x'%record[2]
    #    print ' [-] Unknown2 : 0x%.8x'%record[3]
    #    print ' [-] Unknown3 : 0x%.8x'%record[4]
    #    print ' [-] Unknown4 : 0x%.8x'%record[5]
    #    print ' [-] Unknown5 : 0x%.8x'%record[6]
    #    print ' [-] Unknown6 : 0x%.8x'%record[7]
    #    print ' [-] Record TYPE : 0x%.8x'%record[8]
    #    print ' [-] Data Size : 0x%.8x'%record[9]
    #    print ' [-] Data : %s'%record[10]
    #    tempcount = tempcount + 1


    tableCount, tableEnum = keychain.getTablenametoList(record_list, table_list)

    #COUNT = 0
    #for record_offset in record_list:
    #    record = keychain.get_schema_info_record(fbuf, table_list[0], record_offset)
    #    if record[8] == CSSM_DL_DB_RECORD_GENERIC_PASSWORD: # DBBlob
    #        generic_record = record
    #        generic_offset = COUNT
    #    
    #    elif record[8] == CSSM_DL_DB_RECORD_INTERNET_PASSWORD: # DBBlob
    #        internet_record = record
    #        internet_offset = COUNT
    #    
    #    elif record[8] == CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD: # DBBlob
    #        appleshare_record = record
    #        privatekey_offset = COUNT
    #    
    #    elif record[8] == CSSM_DL_DB_RECORD_METADATA: # DBBlob
    #        dbblob_record = record
    #        dbblob_offset = COUNT
    #    
    #    elif record[8] == CSSM_DL_DB_RECORD_X509_CERTIFICATE:
    #        record_meta_record = record
    #        record_meta_offset = COUNT
    #    
    #    elif record[8] == CSSM_DL_DB_RECORD_PUBLIC_KEY:
    #        publickey_record = record
    #        internet_offset = COUNT
    #    
    #    COUNT = COUNT + 1

    # generate database key
    if password != '':
        masterkey = keychain.generate_master_key(password, fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_METADATA]])
        dbkey = keychain.find_wrapping_key(masterkey, fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_METADATA]])

    elif masterkey != '':
        dbkey = keychain.find_wrapping_key(unhexlify(masterkey), fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_METADATA]])

    else:
        print 'password or keychain:%s' % password
        exit()

    # DEBUG
    print ' [-] DB Key'
    hexdump(dbkey)

    key_list = {}  # keyblob list

    ## get public key blob
    #print '[+] Public Key Table: 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[publickey_offset])
    #table_meta, publickey_list = keychain.get_table(fbuf, table_list[publickey_offset])
    #
    #for publickey_record in publickey_list:
    #    keyblob, ciphertext, iv, return_value = keychain.get_keyblob_record(fbuf, table_list[publickey_offset], publickey_record)
    #    if return_value == 0:
    #        passwd = keychain.decrypted_keyblob(ciphertext, iv ,dbkey)
    #        
    #        key_list[keyblob] = passwd
    #        
    #        #print ' [-] KeyBlob'
    #        #hexdump(keyblob)
    #        #
    #        #print ' [-] Password'
    #        #hexdump(passwd)

    # get symmetric key blob
    print '[+] Symmetric Key Table: 0x%.8x' % (APPL_DB_HEADER_SIZE + table_list[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]])
    table_meta, symmetrickey_list = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]])

    for symmetrickey_record in symmetrickey_list:
        keyblob, ciphertext, iv, return_value = keychain.get_keyblob_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_SYMMETRIC_KEY]],
                                                                            symmetrickey_record)
        if return_value == 0:
            passwd = keychain.decrypted_keyblob(ciphertext, iv, dbkey)
            if passwd != '':
                key_list[keyblob] = passwd

    ## get private key blob
    #print '[+] Private Key Table: 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[privatekey_offset])
    #table_meta, privatekey_list = keychain.get_table(fbuf, table_list[privatekey_offset])
    #
    #for privatekey_record in privatekey_list:
    #    keyblob, ciphertext, iv, return_value = keychain.get_keyblob_record(fbuf, table_list[privatekey_offset], privatekey_record)
    #    if return_value == 0:
    #        passwd = keychain.decrypted_keyblob(ciphertext, iv ,dbkey)
    #        
    #        key_list[keyblob] = passwd
    #        
    #        #print ' [-] KeyBlob'
    #        #hexdump(keyblob)
    #        #
    #        #print ' [-] Password'
    #        #hexdump(passwd)


    ## GET DBBlob Record List
    #print '[+] Generic Password: 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[genericpw_offset])
    table_meta, genericpw_list = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_GENERIC_PASSWORD]])

    ## GET DBBlob Record
    for genericpw in genericpw_list:
        record = keychain.get_genericpw_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_GENERIC_PASSWORD]], genericpw)
        print '[+] Generic Password Record'
        print ' [-] RecordSize : 0x%.8x' % record[0]
        print ' [-] Record Number : 0x%.8x' % record[1]
        #print ' [-] Unknown1 : 0x%.8x'%record[2]
        #print ' [-] Unknown2 : 0x%.8x'%record[3]
        print ' [-] SECURE_STORAGE_GROUP(SSGP) Area : 0x%.8x' % record[4]
        #print ' [-] Secure Storage Group(encrypted blob)'
        #hexdump(record[22])
        try:
            real_key = key_list[record[22][0:20]]
            passwd = keychain.decrypted_db_blob(record[22], real_key)
        except KeyError:
            passwd = ''
        #print ''
        print ' [-] Create DateTime: %s' % record[23]  # 16byte string
        print ' [-] Last Modified DateTime: %s' % record[24]  # 16byte string
        print ' [-] Description : %s' % record[25]
        print ' [-] Creator : %s' % record[26]
        print ' [-] Type : %s' % record[27]
        print ' [-] PrintName : %s' % record[28]
        print ' [-] Alias : %s' % record[29]
        print ' [-] Account : %s' % record[30]
        print ' [-] Service : %s' % record[31]
        print ' [-] Password'
        hexdump(passwd)
        print ''


    #print '[+] Internet: 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[internet_offset])
    table_meta, internetpw_list = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_INTERNET_PASSWORD]])

    for internetpw in internetpw_list:
        record = keychain.get_internetpw_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_INTERNET_PASSWORD]], internetpw)
        print '[+] Internet Record'
        print ' [-] RecordSize : 0x%.8x' % record[0]
        print ' [-] Record Number : 0x%.8x' % record[1]
        #print ' [-] Unknown1 : 0x%.8x'%record[2]
        #print ' [-] Unknown2 : 0x%.8x'%record[3]
        print ' [-] SECURE_STORAGE_GROUP(SSGP) Area : 0x%.8x' % record[4]
        #print ' [-] Secure Storage Group(encrypted blob)'
        #hexdump(record[22])
        try:
            real_key = key_list[record[26][0:20]]
            passwd = keychain.decrypted_db_blob(record[26], real_key)
        except KeyError:
            passwd = ''
        #print ''
        print ' [-] Create DateTime: %s' % record[27]  # 16byte string
        print ' [-] Last Modified DateTime: %s' % record[28]  # 16byte string
        print ' [-] Description : %s' % record[29]
        print ' [-] Comment : %s' % record[30]
        print ' [-] Creator : %s' % record[31]
        print ' [-] Type : %s' % record[32]
        print ' [-] PrintName : %s' % record[33]
        print ' [-] Alias : %s' % record[34]
        print ' [-] Protected : %s' % record[35]
        print ' [-] Account : %s' % record[36]
        print ' [-] SecurityDomain : %s' % record[37]
        print ' [-] Server : %s' % record[38]
        print ' [-] Protocol Type : %s' % PROTOCOL_TYPE[record[39]]
        print ' [-] Auth Type : %s' % AUTH_TYPE[record[40]]
        print ' [-] Port : %d' % record[41]
        print ' [-] Path : %s' % record[42]
        print ' [-] Password'
        hexdump(passwd)
        print ''

    #print '[+] AppleShare Table: 0x%.8x'%(APPL_DB_HEADER_SIZE+table_list[appleshare_offset])
    table_meta, applesharepw_list = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD]])

    for applesharepw in applesharepw_list:
        record = keychain.get_applesharepw_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD]], applesharepw)
        print '[+] AppleShare Record'
        print ' [-] RecordSize : 0x%.8x' % record[0]
        print ' [-] Record Number : 0x%.8x' % record[1]
        #print ' [-] Unknown1 : 0x%.8x'%record[2]
        #print ' [-] Unknown2 : 0x%.8x'%record[3]
        print ' [-] SECURE_STORAGE_GROUP(SSGP) Area : 0x%.8x' % record[4]
        #print ' [-] Secure Storage Group(encrypted blob)'
        #hexdump(record[22])
        try:
            real_key = key_list[record[26][0:20]]
            passwd = keychain.decrypted_db_blob(record[26], real_key)
        except KeyError:
            passwd = ''
        #print ''
        print ' [-] Create DateTime: %s' % record[27]  # 16byte string
        print ' [-] Last Modified DateTime: %s' % record[28]  # 16byte string
        print ' [-] Description : %s' % record[29]
        print ' [-] Comment : %s' % record[30]
        print ' [-] Creator : %s' % record[31]
        print ' [-] Type : %s' % record[32]
        print ' [-] PrintName : %s' % record[33]
        print ' [-] Alias : %s' % record[34]
        print ' [-] Protected : %s' % record[35]
        print ' [-] Account : %s' % record[36]
        print ' [-] Volume : %s' % record[37]
        print ' [-] Server : %s' % record[38]
        print ' [-] Protocol Type : %s' % PROTOCOL_TYPE[record[39]]
        print ' [-] Address : %d' % record[40]
        print ' [-] Signature : %s' % record[41]
        print ' [-] Password'
        hexdump(passwd)
        print ''

    exit()


if __name__ == "__main__":
    main()
