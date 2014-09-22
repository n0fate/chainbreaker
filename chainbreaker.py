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

# struct X509_CERTIFICATE {
#     UINT RecordSize;
#     UINT RecordNumber;
#     UINT Unknown1;
#     UINT Unknown2;
#     UINT CERTSIZE;
#     UINT UNKNOWN3;
#     UINT pCERTTYPE;
#     UINT pCertEncoding;
#     UINT pPrintName;
#     UINT pAlias;
#     UINT pSUbject;
#     UINT pIssuer;
#     UINT pSerialNumber;
#     UINT pSubjectKeyIdentifier;
#     UINT pPublicKeyHash;
# }
X509_CERT_HEADER = '>IIIIIIIIIIIIIII'

# namespace KeySchema {
#
# divert(-1)
# startClass(Key)
# attribute(`  Ss', KeyClass, kSecKeyKeyClass, (char*) "KeyClass", 0, NULL, UINT32)
# attribute(`  Ss', PrintName, kSecKeyPrintName, (char*) "PrintName", 0, NULL, BLOB)
# attribute(`  Ss', Alias, kSecKeyAlias, (char*) "Alias", 0, NULL, BLOB)
# attribute(`  Ss', Permanent, kSecKeyPermanent, (char*) "Permanent", 0, NULL, UINT32)
# attribute(`  Ss', Private, kSecKeyPrivate, (char*) "Private", 0, NULL, UINT32)
# attribute(`  Ss', Modifiable, kSecKeyModifiable, (char*) "Modifiable", 0, NULL, UINT32)
# attribute(`UISs', Label, kSecKeyLabel, (char*) "Label", 0, NULL, BLOB)
# attribute(`U Ss', ApplicationTag, kSecKeyApplicationTag, (char*) "ApplicationTag", 0, NULL, BLOB)
# attribute(`U Ss', KeyCreator, kSecKeyKeyCreator, (char*) "KeyCreator", 0, NULL, BLOB)
# attribute(`U Ss', KeyType, kSecKeyKeyType, (char*) "KeyType", 0, NULL, UINT32)
# attribute(`U Ss', KeySizeInBits, kSecKeyKeySizeInBits, (char*) "KeySizeInBits", 0, NULL, UINT32)
# attribute(`U Ss', EffectiveKeySize, kSecKeyEffectiveKeySize, (char*) "EffectiveKeySize", 0, NULL, UINT32)
# attribute(`U Ss', StartDate, kSecKeyStartDate, (char*) "StartDate", 0, NULL, BLOB)
# attribute(`U Ss', EndDate, kSecKeyEndDate, (char*) "EndDate", 0, NULL, BLOB)
# attribute(`  Ss', Sensitive, kSecKeySensitive, (char*) "Sensitive", 0, NULL, UINT32)
# attribute(`  Ss', AlwaysSensitive, kSecKeyAlwaysSensitive, (char*) "AlwaysSensitive", 0, NULL, UINT32)
# attribute(`  Ss', Extractable, kSecKeyExtractable, (char*) "Extractable", 0, NULL, UINT32)
# attribute(`  Ss', NeverExtractable, kSecKeyNeverExtractable, (char*) "NeverExtractable", 0, NULL, UINT32)
# attribute(` ISs', Encrypt, kSecKeyEncrypt, (char*) "Encrypt", 0, NULL, UINT32)
# attribute(` ISs', Decrypt, kSecKeyDecrypt, (char*) "Decrypt", 0, NULL, UINT32)
# attribute(` ISs', Derive, kSecKeyDerive, (char*) "Derive", 0, NULL, UINT32)
# attribute(` ISs', Sign, kSecKeySign, (char*) "Sign", 0, NULL, UINT32)
# attribute(` ISs', Verify, kSecKeyVerify, (char*) "Verify", 0, NULL, UINT32)
# attribute(` ISs', SignRecover, kSecKeySignRecover, (char*) "SignRecover", 0, NULL, UINT32)
# attribute(` ISs', VerifyRecover, kSecKeyVerifyRecover, (char*) "VerifyRecover", 0, NULL, UINT32)
# attribute(` ISs', Wrap, kSecKeyWrap, (char*) "Wrap", 0, NULL, UINT32)
# attribute(` ISs', Unwrap, kSecKeyUnwrap, (char*) "Unwrap", 0, NULL, UINT32)
# endClass()
#
# } // end namespace KeySchema

# http://web.mit.edu/darwin/src/modules/Security/cdsa/cdsa/cssmtype.h
KEY_TYPE = {
    0x00+0x0F : 'CSSM_KEYCLASS_PUBLIC_KEY',
    0x01+0x0F : 'CSSM_KEYCLASS_PRIVATE_KEY',
    0x02+0x0F : 'CSSM_KEYCLASS_SESSION_KEY',
    0x03+0x0F : 'CSSM_KEYCLASS_SECRET_PART',
    0xFFFFFFFF : 'CSSM_KEYCLASS_OTHER'
}

CSSM_ALGORITHMS = {
    0 : 'CSSM_ALGID_NONE',
    1 : 'CSSM_ALGID_CUSTOM',
    2 : 'CSSM_ALGID_DH',
    3 : 'CSSM_ALGID_PH',
    4 : 'CSSM_ALGID_KEA',
    5 : 'CSSM_ALGID_MD2',
    6 : 'CSSM_ALGID_MD4',
    7 : 'CSSM_ALGID_MD5',
    8 : 'CSSM_ALGID_SHA1',
    9 : 'CSSM_ALGID_NHASH',
    10 : 'CSSM_ALGID_HAVAL:',
    11 : 'CSSM_ALGID_RIPEMD',
    12 : 'CSSM_ALGID_IBCHASH',
    13 : 'CSSM_ALGID_RIPEMAC',
    14 : 'CSSM_ALGID_DES',
    15 : 'CSSM_ALGID_DESX',
    16 : 'CSSM_ALGID_RDES',
    17 : 'CSSM_ALGID_3DES_3KEY_EDE',
    18 : 'CSSM_ALGID_3DES_2KEY_EDE',
    19 : 'CSSM_ALGID_3DES_1KEY_EEE',
    20 : 'CSSM_ALGID_3DES_3KEY_EEE',
    21 : 'CSSM_ALGID_3DES_2KEY_EEE',
    22 : 'CSSM_ALGID_IDEA',
    23 : 'CSSM_ALGID_RC2',
    24 : 'CSSM_ALGID_RC5',
    25 : 'CSSM_ALGID_RC4',
    26 : 'CSSM_ALGID_SEAL',
    27 : 'CSSM_ALGID_CAST',
    28 : 'CSSM_ALGID_BLOWFISH',
    29 : 'CSSM_ALGID_SKIPJACK',
    30 : 'CSSM_ALGID_LUCIFER',
    31 : 'CSSM_ALGID_MADRYGA',
    32 : 'CSSM_ALGID_FEAL',
    33 : 'CSSM_ALGID_REDOC',
    34 : 'CSSM_ALGID_REDOC3',
    35 : 'CSSM_ALGID_LOKI',
    36 : 'CSSM_ALGID_KHUFU',
    37 : 'CSSM_ALGID_KHAFRE',
    38 : 'CSSM_ALGID_MMB',
    39 : 'CSSM_ALGID_GOST',
    40 : 'CSSM_ALGID_SAFER',
    41 : 'CSSM_ALGID_CRAB',
    42 : 'CSSM_ALGID_RSA',
    43 : 'CSSM_ALGID_DSA',
    44 : 'CSSM_ALGID_MD5WithRSA',
    45 : 'CSSM_ALGID_MD2WithRSA',
    46 : 'CSSM_ALGID_ElGamal',
    47 : 'CSSM_ALGID_MD2Random',
    48 : 'CSSM_ALGID_MD5Random',
    49 : 'CSSM_ALGID_SHARandom',
    50 : 'CSSM_ALGID_DESRandom',
    51 : 'CSSM_ALGID_SHA1WithRSA',
    52 : 'CSSM_ALGID_CDMF',
    53 : 'CSSM_ALGID_CAST3',
    54 : 'CSSM_ALGID_CAST5',
    55 : 'CSSM_ALGID_GenericSecret',
    56 : 'CSSM_ALGID_ConcatBaseAndKey',
    57 : 'CSSM_ALGID_ConcatKeyAndBase',
    58 : 'CSSM_ALGID_ConcatBaseAndData',
    59 : 'CSSM_ALGID_ConcatDataAndBase',
    60 : 'CSSM_ALGID_XORBaseAndData',
    61 : 'CSSM_ALGID_ExtractFromKey',
    62 : 'CSSM_ALGID_SSL3PreMasterGen',
    63 : 'CSSM_ALGID_SSL3MasterDerive',
    64 : 'CSSM_ALGID_SSL3KeyAndMacDerive',
    65 : 'CSSM_ALGID_SSL3MD5_MAC',
    66 : 'CSSM_ALGID_SSL3SHA1_MAC',
    67 : 'CSSM_ALGID_PKCS5_PBKDF1_MD5',
    68 : 'CSSM_ALGID_PKCS5_PBKDF1_MD2',
    69 : 'CSSM_ALGID_PKCS5_PBKDF1_SHA1',
    70 : 'CSSM_ALGID_WrapLynks',
    71 : 'CSSM_ALGID_WrapSET_OAEP',
    72 : 'CSSM_ALGID_BATON',
    73 : 'CSSM_ALGID_ECDSA',
    74 : 'CSSM_ALGID_MAYFLY',
    75 : 'CSSM_ALGID_JUNIPER',
    76 : 'CSSM_ALGID_FASTHASH',
    77 : 'CSSM_ALGID_3DES',
    78 : 'CSSM_ALGID_SSL3MD5',
    79 : 'CSSM_ALGID_SSL3SHA1',
    80 : 'CSSM_ALGID_FortezzaTimestamp',
    81 : 'CSSM_ALGID_SHA1WithDSA',
    82 : 'CSSM_ALGID_SHA1WithECDSA',
    83 : 'CSSM_ALGID_DSA_BSAFE',
    84 : 'CSSM_ALGID_ECDH',
    85 : 'CSSM_ALGID_ECMQV',
    86 : 'CSSM_ALGID_PKCS12_SHA1_PBE',
    87 : 'CSSM_ALGID_ECNRA',
    88 : 'CSSM_ALGID_SHA1WithECNRA',
    89 : 'CSSM_ALGID_ECES',
    90 : 'CSSM_ALGID_ECAES',
    91 : 'CSSM_ALGID_SHA1HMAC',
    92 : 'CSSM_ALGID_FIPS186Random',
    93 : 'CSSM_ALGID_ECC',
    94 : 'CSSM_ALGID_MQV',
    95 : 'CSSM_ALGID_NRA',
    96 : 'CSSM_ALGID_IntelPlatformRandom',
    97 : 'CSSM_ALGID_UTC',
    98 : 'CSSM_ALGID_HAVAL3',
    99 : 'CSSM_ALGID_HAVAL4',
    100 : 'CSSM_ALGID_HAVAL5',
    101 : 'CSSM_ALGID_TIGER',
    102 : 'CSSM_ALGID_MD5HMAC',
    103 : 'CSSM_ALGID_PKCS5_PBKDF2',
    104 : 'CSSM_ALGID_RUNNING_COUNTER',
    0x7FFFFFFF : 'CSSM_ALGID_LAST'
}

# http://www.opensource.apple.com/source/Security/Security-55179.1/include/security_cdsa_utilities/KeySchema.h
# http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-36940/lib/SecKey.h
# struct SECKEY_HEADER {
#     UINT RecordSize;
#     UINT RecordNumber;
#     UINT Unknown1;
#     UINT Unknown2;
#     UINT BlobSize;
#     UINT UNKNOWN3;
#     UINT KeyClass; // 0x0F, CSSM_KEYCLASS
#     UINT pPrintName;  // LV. human-readable name
#     UINT Alias;   // current unused
#     UINT Permanent;   // @constant kSecKeyPermanent type uint32, value is nonzero if this key is permanent (stored in some keychain).  This is always 1.
#     UINT Private; // @constant kSecKeyPrivate type uint32, value is nonzero if this key is protected by a user login or a password, or both.
#     UINT Modifiable;
#     UINT Label;   // This contains the hash of the public key. This is used to associate certificates and keys.
#     UINT ApplicationTag;  // currently unused
#     UINT KeyCreator;   // LV, CSSM_GUID structure, moduleid of the csp owning this key.
#     UINT KeyType; // CSSM_ALGORITHMS
#     UINT KeySizeInBits;   // Number of Bits in this key.
#     UINT EffectiveKeySize;   // value is the effective number of bits in this key. For example a des key has 56
#     UINT StartDate;   // CSSM_DATE. Earliest date from which this key may be used. Effective date of key
#     UINT EndDate; // CSSM_DATE. Lastest date at whice this key may be used. Expiration date of key
#     UINT Sensitive;
#     UINT AlwaysSensitive;
#     UINT Extractable; // value is nozero, this key can be wrapped
#     UINT NeverExtractable;
#     UINT Encrypt;    // value is nonzero, this key can be used in a encrypt operation
#     UINT Decrypt;    // value is nonzero, this key can be used in a decrypt operation
#     UINT Derive;
#     UINT Sign;
#     UINT Verify;
#     UINT SignRecover;
#     UINT VerifyRecover;
#     UINT Wrap;    // key can wrap other keys
#     UINT Unwrap;  // key can unwrap other keys
# }
SECKEY_HEADER = '>IIIIIIIIIIIIIIIIIIIIIIIIIIIIIIIII'

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

############ CERT TYPE ##############
CERT_TYPE = {
    0x00 : 'CSSM_CERT_UNKNOWN',
    0x01 : 'CSSM_CERT_X_509v1',
    0x02 : 'CSSM_CERT_X_509v2',
    0x03 : 'CSSM_CERT_X_509v3',
    0x04 : 'CSSM_CERT_PGP',
    0x05 : 'CSSM_CERT_SPKI',
    0x06 : 'CSSM_CERT_SDSIv1',
    0x08 : 'CSSM_CERT_Intel',
    0x09 : 'CSSM_CERT_X_509_ATTRIBUTE',
    0x0A : 'CSSM_CERT_X9_ATTRIBUTE',
    0x0C : 'CSSM_CERT_ACL_ENTRY',
    0x7FFE: 'CSSM_CERT_MULTIPLE',
    0x7FFF : 'CSSM_CERT_LAST',
    0x8000 : 'CSSM_CL_CUSTOM_CERT_TYPE'
}
####################################

########### CERT ENCODING #############
CERT_ENCODING = {
    0x00 : 'CSSM_CERT_ENCODING_UNKNOWN',
    0x01 : 'CSSM_CERT_ENCODING_CUSTOM',
    0x02 : 'CSSM_CERT_ENCODING_BER',
    0x03 : 'CSSM_CERT_ENCODING_DER',
    0x04 : 'CSSM_CERT_ENCODING_NDR',
    0x05 : 'CSSM_CERT_ENCODING_SEXPR',
    0x06 : 'CSSM_CERT_ENCODING_PGP',
    0x7FFE: 'CSSM_CERT_ENCODING_MULTIPLE',
    0x7FFF : 'CSSM_CERT_ENCODING_LAST'
}

STD_APPLE_ADDIN_MODULE = {
    '{87191ca0-0fc9-11d4-849a-000502b52122}': 'CSSM itself',
    '{87191ca1-0fc9-11d4-849a-000502b52122}': 'File based DL (aka "Keychain DL")',
    '{87191ca2-0fc9-11d4-849a-000502b52122}': 'Core CSP (local space)',
    '{87191ca3-0fc9-11d4-849a-000502b52122}': 'Secure CSP/DL (aka "Keychain CSPDL")',
    '{87191ca4-0fc9-11d4-849a-000502b52122}': 'X509 Certificate CL',
    '{87191ca5-0fc9-11d4-849a-000502b52122}': 'X509 Certificate TP',
    '{87191ca6-0fc9-11d4-849a-000502b52122}': 'DLAP/OpenDirectory access DL',
    '{87191ca7-0fc9-11d4-849a-000502b52122}': 'TP for ".mac" related policies',
    '{87191ca8-0fc9-11d4-849a-000502b52122}': 'Smartcard CSP/DL',
    '{87191ca9-0fc9-11d4-849a-000502b52122}': 'DL for ".mac" certificate access'
}

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

    def checkvalidkeychain(self):
        if self.fbuf[0:4] != KEYCHAIN_SIGNATURE:
            return False
        return True

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

    def get_x509_record(self, fbuf, base_addr, offset):
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        record_meta = struct.unpack(X509_CERT_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 60])

        # sorting record data
        #for record_element in record_meta:
        #    record.append(record_element)


        x509CertSize = record_meta[4]

        x509Certificate = fbuf[BASE_ADDR + 60:BASE_ADDR + 60 + x509CertSize]  # record_meta[0] => record size

        pCertType = record_meta[6]-1
        pCertEncoding = record_meta[7]-1

        record.append(struct.unpack('>I', fbuf[BASE_ADDR + pCertType:BASE_ADDR + pCertType + 4])[0]) # Cert Type
        record.append(struct.unpack('>I', fbuf[BASE_ADDR + pCertEncoding:BASE_ADDR + pCertEncoding + 4])[0]) # Cert Encoding

        Count = 0
        for pCol in record_meta[8:]:
            if pCol == 0:
                record.append('')
            else:
                pCol -= 1

                str_length = struct.unpack('>I', fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]

                # 4byte arrangement
                if (str_length % 4) == 0:
                    real_str_len = (str_length / 4) * 4
                else:
                    real_str_len = ((str_length / 4) + 1) * 4
                unpack_value = '>' + str(real_str_len) + 's'

                data = struct.unpack(unpack_value, fbuf[BASE_ADDR + pCol + 4:BASE_ADDR + pCol + 4 + real_str_len])[0]
                record.append(data)

            Count += 1

        record.append(x509Certificate)
        return record

    def get_key_record(self, fbuf, base_addr, offset):  ## PUBLIC and PRIVATE KEY
        record = []

        BASE_ADDR = APPL_DB_HEADER_SIZE + base_addr + offset

        #print BASE_ADDR

        RecordMeta = struct.unpack(SECKEY_HEADER, fbuf[BASE_ADDR:BASE_ADDR + 132])

        # sorting record data
        #for record_element in record_meta:
        #    record.append(record_element)


        KeyBlobSize = RecordMeta[4]

        SIZEOFHEADER = 132

        KeyBlob = fbuf[BASE_ADDR + SIZEOFHEADER:BASE_ADDR + SIZEOFHEADER + KeyBlobSize]  # record_meta[0] => record size

        #hexdump(KeyBlob)

        record_meta = []

        for offset in range(6, len(RecordMeta)):
            record_meta.append(RecordMeta[offset] - 1)


        printname = self.getLV(fbuf, BASE_ADDR, record_meta[1])
        record.append(printname)

        Label = self.getLV(fbuf, BASE_ADDR, record_meta[6])
        record.append(Label)

        kSecKeyClass = self.getInt(fbuf, BASE_ADDR, record_meta[0])
        record.append(kSecKeyClass)

        kSecPrivate = self.getInt(fbuf, BASE_ADDR, record_meta[4])
        record.append(kSecPrivate)

        kSecKeyType = self.getInt(fbuf, BASE_ADDR, record_meta[9])
        record.append(kSecKeyType)

        kSecKeySizeinBits = self.getInt(fbuf, BASE_ADDR, record_meta[10])
        record.append(kSecKeySizeinBits)

        kSecEffectiveKeySize = self.getInt(fbuf, BASE_ADDR, record_meta[11])
        record.append(kSecEffectiveKeySize)

        kSecEncrypted = self.getInt(fbuf, BASE_ADDR, record_meta[16])
        record.append(kSecEncrypted)

        CSSMType = self.getLV(fbuf, BASE_ADDR, record_meta[8])
        record.append(CSSMType.split('\x00')[0])

        IV, Key = self.getEncryptedDatainBlob(KeyBlob)

        record.append(IV)
        record.append(Key)
        return record

    def getEncryptedDatainBlob(self, BlobBuf):
        magicNumber = 0xFADE0711

        BLOBHEADERSIZE = 16

        BlobStruct = struct.unpack('>IIII', BlobBuf[:BLOBHEADERSIZE])

        if BlobStruct[0] != magicNumber:
            return ''

        KeyData = BlobBuf[BlobStruct[2]:BlobStruct[3]]

        return BlobBuf[BLOBHEADERSIZE:BLOBHEADERSIZE+8], KeyData    # IV, Encrypted Data

    def getInt(self, fbuf, BASE_ADDR, pCol):
        return struct.unpack('>I', fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]

    def getLV(self, fbuf, BASE_ADDR, pCol):
        str_length = struct.unpack('>I', fbuf[BASE_ADDR + pCol:BASE_ADDR + pCol + 4])[0]
        # 4byte arrangement
        if (str_length % 4) == 0:
            real_str_len = (str_length / 4) * 4
        else:
            real_str_len = ((str_length / 4) + 1) * 4
        unpack_value = '>' + str(real_str_len) + 's'
        try:
            data = struct.unpack(unpack_value, fbuf[BASE_ADDR + pCol + 4:BASE_ADDR + pCol + 4 + real_str_len])[0]
        except struct.error:
            print 'Length is too long : %d'%real_str_len
            return ''
        return data


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

    # test code
    #http://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55044/lib/KeyItem.cpp
    def decrypted_private_key(self, encryptedblob, iv, dbkey):
        magicCmsIV = unhexlify('4adda22c79e82105')
        plain = kcdecrypt(dbkey, magicCmsIV, encryptedblob)

        if plain.__len__() == 0:
            return ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(len(plain)):
            revplain += plain[len(plain)-1 - i]

        # now the real key gets found. */
        plain = kcdecrypt(dbkey, iv, revplain)

        #hexdump(plain)
        Keyname = plain[:12]    # Copied Buffer when user click on right and copy a key on Keychain Access
        keyblob = plain[12:]

        return Keyname, keyblob

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

    print 'Public Key : %x'%table_list[tableEnum[CSSM_DL_DB_RECORD_PUBLIC_KEY]]
    print 'Private Key : %x'%table_list[tableEnum[CSSM_DL_DB_RECORD_PRIVATE_KEY]]
    #print 'CSSM_DL_DB_RECORD_X509_CERTIFICATE : %x'%table_list[tableEnum[CSSM_DL_DB_RECORD_X509_CERTIFICATE]]

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

    table_meta, x509CertList = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_X509_CERTIFICATE]])

    for x509Cert in x509CertList:
        record = keychain.get_x509_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_X509_CERTIFICATE]], x509Cert)
        print ' [-] Cert Type: %s' %CERT_TYPE[record[0]]
        print ' [-] Cert Encoding: %s' %CERT_ENCODING[record[1]]
        print ' [-] PrintName : %s' % record[2]
        print ' [-] Alias : %s' % record[3]
        print ' [-] Subject'
        hexdump(record[4])
        print ' [-] Issuer :'
        hexdump(record[5])
        print ' [-] SerialNumber'
        hexdump(record[6])
        print ' [-] SubjectKeyIdentifier'
        hexdump(record[7])
        print ' [-] Public Key Hash'
        hexdump(record[8])
        print ' [-] Certificate'
        hexdump(record[9])
        print ''

    table_meta, PublicKeyList = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_PUBLIC_KEY]])
    for PublicKey in PublicKeyList:
        record = keychain.get_key_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_PUBLIC_KEY]], PublicKey)
        print '[+] Public Key Record'
        print ' [-] PrintName: %s' %record[0]
        print ' [-] Label'
        hexdump(record[1])
        print ' [-] Key Class : %s'%KEY_TYPE[record[2]]
        print ' [-] Private : %d'%record[3]
        print ' [-] Key Type : %s'%CSSM_ALGORITHMS[record[4]]
        print ' [-] Key Size : %d bits'%record[5]
        print ' [-] Effective Key Size : %d bits'%record[6]
        print ' [-] Extracted : %d'%record[7]
        print ' [-] CSSM Type : %s' %STD_APPLE_ADDIN_MODULE[record[8]]
        print ' [-] Public Key'
        hexdump(record[10])

    table_meta, PrivateKeyList = keychain.get_table(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_PRIVATE_KEY]])
    for PrivateKey in PrivateKeyList:
        record = keychain.get_key_record(fbuf, table_list[tableEnum[CSSM_DL_DB_RECORD_PRIVATE_KEY]], PrivateKey)
        print '[+] Private Key Record'
        print ' [-] PrintName: %s' %record[0]
        print ' [-] Label'
        hexdump(record[1])
        print ' [-] Key Class : %s'%KEY_TYPE[record[2]]
        print ' [-] Private : %d'%record[3]
        print ' [-] Key Type : %s'%CSSM_ALGORITHMS[record[4]]
        print ' [-] Key Size : %d bits'%record[5]
        print ' [-] Effective Key Size : %d bits'%record[6]
        print ' [-] Extracted : %d'%record[7]
        print ' [-] CSSM Type : %s' %STD_APPLE_ADDIN_MODULE[record[8]]
        keyname, privatekey = keychain.decrypted_private_key(record[10], record[9], dbkey)
        print ' [-] Key Name'
        hexdump(keyname)
        print ' [-] Decrypted Private Key'
        hexdump(privatekey)

    exit()


if __name__ == "__main__":
    main()
