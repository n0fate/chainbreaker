#!/usr/bin/python

# Author : n0fate
# E-Mail rapfer@gmail.com, n0fate@n0fate.com
#
# 10/7/2020 - Significant changes made by luke@socially-inept.net
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
import struct
from pbkdf2 import PBKDF2
from schema import *
from schema import _APPL_DB_HEADER, _APPL_DB_SCHEMA, _TABLE_HEADER, _DB_BLOB, _GENERIC_PW_HEADER, \
    _KEY_BLOB_REC_HEADER, _KEY_BLOB, _SSGP, _INTERNET_PW_HEADER, _APPLE_SHARE_HEADER, _X509_CERT_HEADER, _SECKEY_HEADER, \
    _UNLOCK_BLOB, _KEYCHAIN_TIME, _INT, _FOUR_CHAR_CODE, _LV, _TABLE_ID, _RECORD_OFFSET
from pyDes import TripleDES, CBC
from binascii import unhexlify, hexlify
import logging
import base64
import string
import uuid

class Chainbreaker(object):
    ATOM_SIZE = 4
    KEYCHAIN_SIGNATURE = "kych"
    BLOCKSIZE = 8
    KEYLEN = 24
    MAGIC_CMS_IV = unhexlify('4adda22c79e82105')
    KEYCHAIN_LOCKED_SIGNATURE = '[Invalid Password / Keychain Locked]'

    def __init__(self, filepath, unlock_password=None, unlock_key=None, unlock_file=None):
        self._filepath = None
        self._unlock_password = None
        self._unlock_key = None
        self._unlock_file = None
        self._db_key = None

        # Raw buffer of keychain file contents
        self.kc_buffer = ''

        self.header = None
        self.schema_info = None
        self.table_list = None
        self.table_metadata = None
        self.record_list = None
        self.table_count = None
        self.table_enum = None
        self.symmetric_key_list = None
        self.symmetric_key_offset = None
        self.dbblob = None
        self.locked = True

        self.logger = logging.getLogger('Chainbreaker')

        self.key_list = {}

        self.db_key = None

        self.filepath = filepath

        if not self._is_valid_keychain():
            self.logger.warning('Keychain signature does not match. are you sure this is a valid keychain file?')

        self.unlock_password = unlock_password
        self.unlock_key = unlock_key
        self.unlock_file = unlock_file

    # Returns a list of GenericPasswordRecord objects extracted from the Keychain
    def dump_generic_passwords(self):
        entries = []
        try:
            table_metadata, generic_pw_list = self._get_table_from_type(CSSM_DL_DB_RECORD_GENERIC_PASSWORD)

            for generic_pw_id in generic_pw_list:
                entries.append(self._get_generic_password_record(generic_pw_id))

        except KeyError:
            self.logger.warning('[!] Generic Password Table is not available')

        return entries

    # Returns a list of InterertPasswordRecord objects extracted from the Keychain
    def dump_internet_passwords(self):
        entries = []
        try:
            table_metadata, internet_pw_list = self._get_table_from_type(CSSM_DL_DB_RECORD_INTERNET_PASSWORD)

            for internet_pw_id in internet_pw_list:
                entries.append(self._get_internet_password_record(internet_pw_id))

        except KeyError:
            self.logger.warning('[!] Internet Password Table is not available')
        return entries

    # Returns a list of AppleshareRecord objects extracted from the Keychain
    def dump_appleshare_passwords(self):
        entries = []
        try:
            table_metadata, appleshare_pw_list = self._get_table_from_type(CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD)

            for appleshare_pw_offset in appleshare_pw_list:
                entries.append(self._get_appleshare_record(appleshare_pw_offset))

        except KeyError:
            self.logger.warning('[!] Appleshare Records Table is not available')
        return entries

    # Returns a list of X509CertfificateRecord objects extracted from the Keychain
    def dump_x509_certificates(self):
        entries = []
        try:
            table_metadata, x509_cert_list = self._get_table_from_type(CSSM_DL_DB_RECORD_X509_CERTIFICATE)

            for i, x509_cert_offset in enumerate(x509_cert_list, 1):
                entries.append(self._get_x_509_record(x509_cert_offset))

        except KeyError:
            self.logger.warning('[!] Certificate Table is not available')

        return entries

    # Returns a list of PublicKeyRecord objects extracted from the Keychain
    def dump_public_keys(self):
        entries = []
        try:
            table_metadata, public_key_list = self._get_table_from_type(CSSM_DL_DB_RECORD_PUBLIC_KEY)
            for public_key_offset in public_key_list:
                entries.append(
                    self._get_public_key_record(public_key_offset))
        except KeyError:
            self.logger.warning('[!] Public Key Table is not available')
        return entries

    # Returns a list of PrivateKeyRecord objects extracted from the Keychain
    def dump_private_keys(self):
        entries = []
        try:
            table_meta, private_key_list = self._get_table_from_type(CSSM_DL_DB_RECORD_PRIVATE_KEY)
            for i, private_key_offset in enumerate(private_key_list, 1):
                entries.append(
                    self._get_private_key_record(private_key_offset))

        except KeyError:
            self.logger.warning('[!] Private Key Table is not available')
        return entries

    # Attempts to read the keychain file into self.kc_buffer
    # On success it extracts out relevant information (table information, key offsets, and the DB BLob)
    def _read_keychain_to_buffer(self):
        try:
            with open(self.filepath, 'rb') as fp:
                self.kc_buffer = fp.read()

            if self.kc_buffer:
                self.header = _APPL_DB_HEADER(self.kc_buffer[:_APPL_DB_HEADER.STRUCT.size])
                self.schema_info, self.table_list = self._get_schema_info(self.header.SchemaOffset)
                self.table_metadata, self.record_list = self._get_table(self.table_list[0])
                self.table_count, self.table_enum = self._get_table_name_to_list(self.record_list, self.table_list)

                self.symmetric_key_offset = self.table_list[self.table_enum[CSSM_DL_DB_RECORD_METADATA]]

                self.base_addr = _APPL_DB_HEADER.STRUCT.size + self.symmetric_key_offset + 0x38
                self.dbblob = _DB_BLOB(self.kc_buffer[self.base_addr:self.base_addr + _DB_BLOB.STRUCT.size])

        except OSError as e:
            self.logger.critical("Unable to read keychain: %s" % e)

    # Simple check to make sure the keychain we're looking at is valid.
    # A valid keychain begins with "kych"
    def _is_valid_keychain(self):
        if self.kc_buffer[0:4] != Chainbreaker.KEYCHAIN_SIGNATURE:
            return False
        return True

    # When the keychain is successfully decrypted ("unlocked"), we can obtain a list of encryption keys
    # used to encrypt individual records, indexed off of the SSGB label.
    def _generate_key_list(self):
        table_meta_data, symmetric_key_list = self._get_table_from_type(CSSM_DL_DB_RECORD_SYMMETRIC_KEY)

        for symmetric_key_record in symmetric_key_list:
            keyblob, ciphertext, iv, return_value = self._get_keyblob_record(symmetric_key_record)
            if return_value == 0:
                password = Chainbreaker.keyblob_decryption(ciphertext, iv, self.db_key)
                if password != '':
                    self.key_list[keyblob] = password

        return len(self.key_list)

    # Returns basic schema (table count, size) and a list of the tables from the Keychain file.
    def _get_schema_info(self, offset):
        table_list = []
        schema_info = _APPL_DB_SCHEMA(self.kc_buffer[offset:offset + _APPL_DB_SCHEMA.STRUCT.size])

        for i in xrange(schema_info.TableCount):
            base_addr = _APPL_DB_HEADER.STRUCT.size + _APPL_DB_SCHEMA.STRUCT.size
            table_list.append(_TABLE_ID(self.kc_buffer[base_addr + (Chainbreaker.ATOM_SIZE * i):base_addr + (
                    Chainbreaker.ATOM_SIZE * i) + Chainbreaker.ATOM_SIZE]).Value)

        return schema_info, table_list

    # Given a table name, return the offset for the table
    def _get_table_offset(self, table_name):
        return self.table_list[self.table_enum[table_name]]

    # Returns a table, given the AppleFileDL CSSM_DB_RECORDTYPE from schema.py
    # (e.g. CSSM_DL_DB_RECORD_GENERIC_PASSWORD)
    def _get_table_from_type(self, table_type):
        return self._get_table(self._get_table_offset(table_type))

    # Returns a both the metadata and a record list for a table, given an offset.
    def _get_table(self, offset):
        record_list = []

        base_addr = _APPL_DB_HEADER.STRUCT.size + offset
        table_metadata = _TABLE_HEADER(self.kc_buffer[base_addr:base_addr + _TABLE_HEADER.STRUCT.size])
        record_offset_base = base_addr + _TABLE_HEADER.STRUCT.size

        record_count = 0
        offset = 0
        while table_metadata.RecordCount != record_count:
            record_offset = _RECORD_OFFSET(self.kc_buffer[
                                           record_offset_base + (Chainbreaker.ATOM_SIZE * offset):record_offset_base + (
                                                   Chainbreaker.ATOM_SIZE * offset) + Chainbreaker.ATOM_SIZE]).Value

            if (record_offset != 0x00) and (record_offset % 4 == 0):
                record_list.append(record_offset)
                record_count += 1
            offset += 1

        return table_metadata, record_list

    # Returns a dict of table indexes keyed off of the TableId
    def _get_table_name_to_list(self, record_list, table_list):
        table_dict = {}
        for count in xrange(len(record_list)):
            table_metadata, generic_list = self._get_table(table_list[count])
            table_dict[table_metadata.TableId] = count  # extract valid table list

        return len(record_list), table_dict

    def _get_keyblob_record(self, record_offset):

        base_addr = self._get_base_address(CSSM_DL_DB_RECORD_SYMMETRIC_KEY, record_offset)

        key_blob_record_header = _KEY_BLOB_REC_HEADER(
            self.kc_buffer[base_addr:base_addr + _KEY_BLOB_REC_HEADER.STRUCT.size])

        record = self.kc_buffer[
                 base_addr + _KEY_BLOB_REC_HEADER.STRUCT.size:base_addr + key_blob_record_header.RecordSize]

        key_blob_record = _KEY_BLOB(record[:+_KEY_BLOB.STRUCT.size])

        if SECURE_STORAGE_GROUP != str(record[key_blob_record.TotalLength + 8:key_blob_record.TotalLength + 8 + 4]):
            return '', '', '', 1

        cipher_len = key_blob_record.TotalLength - key_blob_record.StartCryptoBlob
        if cipher_len % Chainbreaker.BLOCKSIZE != 0:
            self.logger.debug("Bad ciphertext length.")
            return '', '', '', 1

        cipher_text = record[key_blob_record.StartCryptoBlob:key_blob_record.TotalLength]

        # match data, keyblob_ciphertext, Initial Vector, success
        return record[
               key_blob_record.TotalLength + 8:key_blob_record.TotalLength + 8 + 20], cipher_text, key_blob_record.IV, 0

    # Get a timestamp from the keychain buffer
    def _get_keychain_time(self, base_addr, pcol):
        if pcol <= 0:
            return ''
        else:
            return _KEYCHAIN_TIME(self.kc_buffer[base_addr + pcol:base_addr + pcol + _KEYCHAIN_TIME.STRUCT.size]).Time

    # Get an integer from the keychain buffer
    def _get_int(self, base_addr, pcol):
        if pcol <= 0:
            return 0
        else:
            return _INT(self.kc_buffer[base_addr + pcol:base_addr + pcol + 4]).Value

    # Get 4 character code from the keychain buffer
    def _get_four_char_code(self, base_addr, pcol):
        if pcol <= 0:
            return ''
        else:
            return _FOUR_CHAR_CODE(self.kc_buffer[base_addr + pcol:base_addr + pcol + 4]).Value

    # Get an lv from the keychain buffer
    def _get_lv(self, base_addr, pcol):
        if pcol <= 0:
            return ''

        str_length = _INT(self.kc_buffer[base_addr + pcol:base_addr + pcol + 4]).Value
        # 4byte arrangement
        if (str_length % 4) == 0:
            real_str_len = (str_length / 4) * 4
        else:
            real_str_len = ((str_length / 4) + 1) * 4

        try:
            data = _LV(self.kc_buffer[base_addr + pcol + 4:base_addr + pcol + 4 + real_str_len], real_str_len).Value
        except struct.error:
            self.logger.debug('LV string length is too long.')
            return ''

        return data

    #
    # # http://opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-55044/lib/KeyItem.cpp
    def _private_key_decryption(self, encryptedblob, iv):
        plain = Chainbreaker._kcdecrypt(self.db_key, Chainbreaker.MAGIC_CMS_IV, encryptedblob)

        if plain.__len__() == 0:
            return '', ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(len(plain)):
            revplain += plain[len(plain) - 1 - i]

        # now the real key gets found. */
        plain = Chainbreaker._kcdecrypt(self.db_key, iv, revplain)

        keyname = plain[:12]  # Copied Buffer when user click on right and copy a key on Keychain Access
        keyblob = plain[12:]

        return keyname, keyblob

    # ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    def _generate_master_key(self, pw):
        return str(PBKDF2(pw, str(bytearray(self.dbblob.Salt)), 1000, Chainbreaker.KEYLEN))

    # ## find DBBlob and extract Wrapping key
    def _find_wrapping_key(self, master):
        # get cipher text area
        ciphertext = self.kc_buffer[
                     self.base_addr + self.dbblob.StartCryptoBlob:self.base_addr + self.dbblob.TotalLength]

        # decrypt the key
        plain = Chainbreaker._kcdecrypt(master, self.dbblob.IV, ciphertext)

        if plain.__len__() < Chainbreaker.KEYLEN:
            return ''

        dbkey = plain[:Chainbreaker.KEYLEN]

        # return encrypted wrapping key
        return dbkey

    # Extract the Cyphertext, IV, and Salt for the keychain file, for use with offline cracking (e.g. Hashcat)
    # Returns a KeychainPasswordHash object
    def dump_keychain_password_hash(self):
        cyphertext = hexlify(
            self.kc_buffer[self.base_addr + self.dbblob.StartCryptoBlob:self.base_addr + self.dbblob.TotalLength])

        iv = hexlify(self.dbblob.IV)
        salt = hexlify(self.dbblob.Salt)

        return self.KeychainPasswordHash(salt, iv, cyphertext)

    # Given a base address and offset (ID) of a record,
    def _get_appleshare_record(self, record_offset):
        base_addr = self._get_base_address(CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD, record_offset)

        record_meta = _APPLE_SHARE_HEADER(self.kc_buffer[base_addr:base_addr + _APPLE_SHARE_HEADER.STRUCT.size])

        buffer = self.kc_buffer[base_addr + _APPLE_SHARE_HEADER.STRUCT.size:base_addr + record_meta.RecordSize]

        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.AppleshareRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            comment=self._get_lv(base_addr, record_meta.Comment & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            protected=self._get_lv(base_addr, record_meta.Protected & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            volume=self._get_lv(base_addr, record_meta.Volume & 0xFFFFFFFE),
            server=self._get_lv(base_addr, record_meta.Server & 0xFFFFFFFE),
            protocol_type=self._get_four_char_code(base_addr, record_meta.Protocol & 0xFFFFFFFE),
            address=self._get_lv(base_addr, record_meta.Address & 0xFFFFFFFE),
            signature=self._get_lv(base_addr, record_meta.Signature & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey
        )

    def _get_private_key_record(self, record_offset):
        record = self._get_key_record(self._get_table_offset(CSSM_DL_DB_RECORD_PRIVATE_KEY), record_offset)

        if not self.db_key:
            keyname = privatekey = Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE
        else:
            keyname, privatekey = self._private_key_decryption(record[10], record[9])
        return self.PrivateKeyRecord(
            print_name=record[0],
            label=record[1],
            key_class=KEY_TYPE[record[2]],
            private=record[3],
            key_type=record[4],
            key_size=record[5],
            effective_key_size=record[6],
            extracted=record[7],
            cssm_type=record[8],
            iv=record[9],
            key=record[10],
            key_name=keyname,
            private_key=privatekey,
        )

    def _get_public_key_record(self, record_offset):
        record = self._get_key_record(self._get_table_offset(CSSM_DL_DB_RECORD_PUBLIC_KEY), record_offset)
        return self.PublicKeyRecord(
            print_name=record[0],
            label=record[1],
            key_class=KEY_TYPE[record[2]],
            private=record[3],
            key_type=record[4],
            key_size=record[5],
            effective_key_size=record[6],
            extracted=record[7],
            cssm_type=record[8],
            iv=record[9],
            public_key=record[10],
        )

    def _get_key_record(self, table_name, record_offset):  ## PUBLIC and PRIVATE KEY
        base_addr = self._get_base_address(table_name, record_offset)

        record_meta = _SECKEY_HEADER(self.kc_buffer[base_addr:base_addr + _SECKEY_HEADER.STRUCT.size])

        key_blob = self.kc_buffer[
                   base_addr + _SECKEY_HEADER.STRUCT.size:base_addr + _SECKEY_HEADER.STRUCT.size + record_meta.BlobSize]

        iv, key = Chainbreaker._get_encrypted_data_in_blob(key_blob)

        return [self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
                self._get_lv(base_addr, record_meta.Label & 0xFFFFFFFE),
                self._get_int(base_addr, record_meta.KeyClass & 0xFFFFFFFE),
                self._get_int(base_addr, record_meta.Private & 0xFFFFFFFE),
                CSSM_ALGORITHMS[self._get_int(base_addr, record_meta.KeyType & 0xFFFFFFFE)],
                self._get_int(base_addr, record_meta.KeySizeInBits & 0xFFFFFFFE),
                self._get_int(base_addr, record_meta.EffectiveKeySize & 0xFFFFFFFE),
                self._get_int(base_addr, record_meta.Extractable & 0xFFFFFFFE),
                STD_APPLE_ADDIN_MODULE[
                    str(self._get_lv(base_addr, record_meta.KeyCreator & 0xFFFFFFFE)).split('\x00')[0]],
                iv,
                key]

    def _get_x_509_record(self, record_offset):
        base_addr = self._get_base_address(CSSM_DL_DB_RECORD_X509_CERTIFICATE, record_offset)

        record_meta = _X509_CERT_HEADER(self.kc_buffer[base_addr:base_addr + _X509_CERT_HEADER.STRUCT.size])

        return self.X509CertificateRecord(
            type=self._get_int(base_addr, record_meta.CertType & 0xFFFFFFFE),
            encoding=self._get_int(base_addr, record_meta.CertEncoding & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            subject=self._get_lv(base_addr, record_meta.Subject & 0xFFFFFFFE),
            issuer=self._get_lv(base_addr, record_meta.Issuer & 0xFFFFFFFE),
            serial_number=self._get_lv(base_addr, record_meta.SerialNumber & 0xFFFFFFFE),
            subject_key_identifier=self._get_lv(base_addr, record_meta.SubjectKeyIdentifier & 0xFFFFFFFE),
            public_key_hash=self._get_lv(base_addr, record_meta.PublicKeyHash & 0xFFFFFFFE),
            certificate=self.kc_buffer[
                        base_addr + _X509_CERT_HEADER.STRUCT.size:base_addr + _X509_CERT_HEADER.STRUCT.size + record_meta.CertSize]
        )

    def _extract_ssgp_and_dbkey(self, record_meta, buffer):
        ssgp = None
        dbkey = None

        if record_meta.SSGPArea != 0:
            ssgp = _SSGP(buffer[:record_meta.SSGPArea])
            dbkey_index = ssgp.Magic + ssgp.Label

            if dbkey_index in self.key_list:
                dbkey = self.key_list[dbkey_index]

        return ssgp, dbkey

    def _get_internet_password_record(self, record_offset):
        base_addr = self._get_base_address(CSSM_DL_DB_RECORD_INTERNET_PASSWORD, record_offset)
        record_meta = _INTERNET_PW_HEADER(self.kc_buffer[base_addr:base_addr + _INTERNET_PW_HEADER.STRUCT.size])

        buffer = self.kc_buffer[base_addr + _INTERNET_PW_HEADER.STRUCT.size:base_addr + record_meta.RecordSize]

        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.InternetPasswordRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            comment=self._get_lv(base_addr, record_meta.Comment & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            protected=self._get_lv(base_addr, record_meta.Protected & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            security_domain=self._get_lv(base_addr, record_meta.SecurityDomain & 0xFFFFFFFE),
            server=self._get_lv(base_addr, record_meta.Server & 0xFFFFFFFE),
            protocol_type=self._get_four_char_code(base_addr, record_meta.Protocol & 0xFFFFFFFE),
            auth_type=self._get_lv(base_addr, record_meta.AuthType & 0xFFFFFFFE),
            port=self._get_int(base_addr, record_meta.Port & 0xFFFFFFFE),
            path=self._get_lv(base_addr, record_meta.Path & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey
        )

    def _get_generic_password_record(self, record_offset):
        base_addr = self._get_base_address(CSSM_DL_DB_RECORD_GENERIC_PASSWORD, record_offset)

        record_meta = _GENERIC_PW_HEADER(self.kc_buffer[base_addr:base_addr + _GENERIC_PW_HEADER.STRUCT.size])

        buffer = self.kc_buffer[
                 base_addr + _GENERIC_PW_HEADER.STRUCT.size:base_addr + record_meta.RecordSize]

        ssgp, dbkey = self._extract_ssgp_and_dbkey(record_meta, buffer)

        return self.GenericPasswordRecord(
            created=self._get_keychain_time(base_addr, record_meta.CreationDate & 0xFFFFFFFE),
            last_modified=self._get_keychain_time(base_addr, record_meta.ModDate & 0xFFFFFFFE),
            description=self._get_lv(base_addr, record_meta.Description & 0xFFFFFFFE),
            creator=self._get_four_char_code(base_addr, record_meta.Creator & 0xFFFFFFFE),
            type=self._get_four_char_code(base_addr, record_meta.Type & 0xFFFFFFFE),
            print_name=self._get_lv(base_addr, record_meta.PrintName & 0xFFFFFFFE),
            alias=self._get_lv(base_addr, record_meta.Alias & 0xFFFFFFFE),
            account=self._get_lv(base_addr, record_meta.Account & 0xFFFFFFFE),
            service=self._get_lv(base_addr, record_meta.Service & 0xFFFFFFFE),
            ssgp=ssgp,
            dbkey=dbkey)

        return record

    def _get_base_address(self, table_name, offset=None):
        base_address = _APPL_DB_HEADER.STRUCT.size + self._get_table_offset(table_name)
        if offset:
            base_address += offset

        return base_address

    @property
    def filepath(self):
        return self._filepath

    @filepath.setter
    def filepath(self, value):
        self._filepath = value
        if self._filepath:
            self._read_keychain_to_buffer()

    @property
    def unlock_password(self):
        return self._unlock_password

    @unlock_password.setter
    def unlock_password(self, unlock_password):
        self._unlock_password = unlock_password

        if self._unlock_password:
            master_key = self._generate_master_key(self._unlock_password)
            self.db_key = self._find_wrapping_key(master_key)

    @property
    def unlock_key(self):
        return self._unlock_key

    @unlock_key.setter
    def unlock_key(self, unlock_key):
        self._unlock_key = unlock_key

        if self._unlock_key:
            self.db_key = self._find_wrapping_key(unhexlify(self._unlock_key))

    @property
    def unlock_file(self):
        return self._unlock_file

    @unlock_file.setter
    def unlock_file(self, filepath):
        self._unlock_file = filepath

        if self._unlock_file:
            try:
                with open(self._unlock_file, mode='rb') as uf:
                    file_content = uf.read()

                unlock_key_blob = _UNLOCK_BLOB(file_content)
                self.db_key = self._find_wrapping_key(unlock_key_blob.MasterKey)
            except OSError:
                logger.warning("Unable to read unlock file: %s" % self._unlock_file)

    @property
    def db_key(self):
        return self._db_key

    @db_key.setter
    def db_key(self, key):
        self._db_key = key

        if self._db_key:
            # Even after finding a db_key, we need to try and load the key list.
            # If we don't find any keys, but we do find a db_key, then we've likely
            # found a hash collision
            if self._generate_key_list() > 0:
                self.locked = False

    # SOURCE : extractkeychain.py
    @staticmethod
    def _kcdecrypt(key, iv, data):
        logger = logging.getLogger('Chainbreaker')
        if len(data) == 0:
            logger.debug("Encrypted data is 0.")
            return ''

        if len(data) % Chainbreaker.BLOCKSIZE != 0:
            return ''

        cipher = TripleDES(key, CBC, str(bytearray(iv)))

        plain = cipher.decrypt(data)

        # now check padding
        pad = ord(plain[-1])
        if pad > 8:
            logger.debug("Bad padding byte. Keychain password might be incorrect.")
            return ''

        for z in plain[-pad:]:
            if ord(z) != pad:
                logger.debug("Bad padding byte. Keychain password might be incorrect.")
                return ''

        plain = plain[:-pad]

        return plain

    @staticmethod
    def _get_encrypted_data_in_blob(blob_buffer):
        key_blob = _KEY_BLOB(blob_buffer[:_KEY_BLOB.STRUCT.size])

        if key_blob.CommonBlob.Magic != _KEY_BLOB.COMMON_BLOB_MAGIC:
            return '', ''

        key_data = blob_buffer[key_blob.StartCryptoBlob:key_blob.TotalLength]
        return key_blob.IV, key_data  # IV, Encrypted Data

    # ## decrypted dbblob area
    # ## Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    # ## http://www.opensource.apple.com/source/libsecurity_keychain/libsecurity_keychain-36620/lib/StorageManager.cpp
    # def _ssgp_decryption(self, ssgp, dbkey):
    #     return Chainbreaker._kcdecrypt(dbkey, _SSGP(ssgp).IV, ssgp[_SSGP.STRUCT.size:])

    # Documents : http://www.opensource.apple.com/source/securityd/securityd-55137.1/doc/BLOBFORMAT
    # source : http://www.opensource.apple.com/source/libsecurity_cdsa_client/libsecurity_cdsa_client-36213/lib/securestorage.cpp
    # magicCmsIV : http://www.opensource.apple.com/source/Security/Security-28/AppleCSP/AppleCSP/wrapKeyCms.cpp
    @staticmethod
    def keyblob_decryption(encryptedblob, iv, dbkey):
        logger = logging.getLogger('Chainbreaker')

        # magicCmsIV = unhexlify('4adda22c79e82105')
        plain = Chainbreaker._kcdecrypt(dbkey, Chainbreaker.MAGIC_CMS_IV, encryptedblob)

        if plain.__len__() == 0:
            return ''

        # now we handle the unwrapping. we need to take the first 32 bytes,
        # and reverse them.
        revplain = ''
        for i in range(32):
            revplain += plain[31 - i]

        # now the real key gets found. */
        plain = Chainbreaker._kcdecrypt(dbkey, iv, revplain)

        keyblob = plain[4:]

        if len(keyblob) != Chainbreaker.KEYLEN:
            logger.debug("Decrypted key length is not valid")
            return ''

        return keyblob

    class KeychainRecord(object):
        def __init__(self):
            self.logger = logging.getLogger('Chainbreaker')

        def write_to_disk(self, output_directory):
            # self.exportable contains the content we should write to disk. If it isn't implemented we can't
            # then writing to disk via this method isn't currently supported.
            try:
                export_content = self.exportable
            except NotImplementedError:
                self.logger.warning('Attempted to export a non-exportable record.')
                return False

            # Create out export directory if it doesn't exist.
            if not os.path.exists(output_directory):
                try:
                    os.makedirs(output_directory)
                except OSError:
                    self.logger.critical('Unable to create export directory: %s' % output_directory)

            # Generate our filepath, making sure the file doesn't already exist. If it does,
            # add a number, e.g. PrivateKey.1.key
            file_name = self.FileName + self.FileExt
            iteration = 1
            while os.path.exists(os.path.join(output_directory, file_name)):
                file_name = "%s.%s%s" % (self.FileName, iteration, self.FileExt)
                iteration += 1

            file_path = os.path.join(output_directory, file_name)

            # Finish exporting the record.
            try:
                with open(file_path, 'wb') as fp:
                    self.logger.info('\t [-] Exported: %s' % file_path)
                    fp.write(export_content)
                    return True
            except OSError, e:
                self.logger.critical('Exception while attempting to export %s: %s' % (file_path, e))

        @property
        def FileName(self):
            return str(uuid.uuid4())

        @property
        def FileExt(self):
            return '.txt'

    class KeychainPasswordHash(KeychainRecord):
        KEYCHAIN_PASSWORD_HASH_FORMAT = "$keychain$*%s*%s*%s"

        def __init__(self, salt, iv, cyphertext):
            self.salt = salt
            self.iv = iv
            self.cypher_text = cyphertext

            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self):
            return Chainbreaker.KeychainPasswordHash.KEYCHAIN_PASSWORD_HASH_FORMAT % (
                self.salt, self.iv, self.cypher_text)

        @property
        def exportable(self):
            return self.__str__()

        @property
        def FileName(self):
            return "keychain_password_hash"

    class PublicKeyRecord(KeychainRecord):
        def __init__(self, print_name=None, label=None, key_class=None, private=None, key_type=None, key_size=None,
                     effective_key_size=None, extracted=None, cssm_type=None, public_key=None, iv=None, key=None):
            self.PrintName = print_name
            self.Label = label
            self.KeyClass = key_class
            self.Private = private
            self.KeyType = key_type
            self.KeySize = key_size
            self.EffectiveKeySize = effective_key_size
            self.Extracted = extracted
            self.CSSMType = cssm_type
            self.PublicKey = public_key
            self.IV = iv
            self.Key = key

            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self):
            output = '[+] Public Key\n'
            output += ' [-] Print Name: %s\n' % self.PrintName
            # output += ' [-] Label: %s\n' % self.Label
            output += ' [-] Key Class: %s\n' % self.KeyClass
            output += ' [-] Private: %s\n' % self.Private
            output += ' [-] Key Type: %s\n' % self.KeyType
            output += ' [-] Key Size: %s\n' % self.KeySize
            output += ' [-] Effective Key Size: %s\n' % self.EffectiveKeySize
            output += ' [-] Extracted: %s\n' % self.Extracted
            output += ' [-] CSSM Type: %s\n' % self.CSSMType
            output += ' [-] Base64 Encoded Public Key: %s\n' % base64.b64encode(self.PublicKey)
            return output

        @property
        def exportable(self):
            return self.PublicKey

        @property
        def FileName(self):
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self):
            return '.pub'

    class PrivateKeyRecord(KeychainRecord):
        def __init__(self, print_name=None, label=None, key_class=None, private=None, key_type=None, key_size=None,
                     effective_key_size=None, extracted=None, cssm_type=None, key_name=None, private_key=None, iv=None,
                     key=None):
            self.PrintName = print_name
            self.Label = label
            self.KeyClass = key_class
            self.Private = private
            self.KeyType = key_type
            self.KeySize = key_size
            self.EffectiveKeySize = effective_key_size
            self.Extracted = extracted
            self.CSSMType = cssm_type
            self.KeyName = key_name
            self.PrivateKey = private_key
            self.IV = iv
            self.Key = key

            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self):
            output = '[+] Private Key\n'
            output += ' [-] Print Name: %s\n' % self.PrintName
            # output += ' [-] Label: %s\n' % self.Label
            output += ' [-] Key Class: %s\n' % self.KeyClass
            # output += ' [-] Private: %s\n' % self.Private
            output += ' [-] Key Type: %s\n' % self.KeyType
            output += ' [-] Key Size: %s\n' % self.KeySize
            output += ' [-] Effective Key Size: %s\n' % self.EffectiveKeySize
            # output += ' [-] Extracted: %s\n' % self.Extracted
            output += ' [-] CSSM Type: %s\n' % self.CSSMType
            # output += ' [-] KeyName: %s\n' % self.KeyName

            output += ' [-] Base64 Encoded PrivateKey: '
            if self.PrivateKey == Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE:
                output += "%s\n" % Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE
            else:
                output += "%s\n" % base64.b64encode(self.PrivateKey)

            return output

        @property
        def exportable(self):
            return self.PrivateKey

        @property
        def FileName(self):
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self):
            return '.key'

    class X509CertificateRecord(KeychainRecord):
        def __init__(self, type=None, encoding=None, print_name=None, alias=None, subject=None, issuer=None,
                     serial_number=None, subject_key_identifier=None, public_key_hash=None, certificate=None):
            self.Type = type
            self.Encoding = encoding
            self.PrintName = print_name
            self.Alias = alias
            self.Subject = subject
            self.Issuer = issuer
            self.Serial_Number = serial_number
            self.Subject_Key_Identifier = subject_key_identifier
            self.Public_Key_Hash = public_key_hash
            self.Certificate = certificate

            Chainbreaker.KeychainRecord.__init__(self)

        def __str__(self):
            output = '[+] X509 Certificate\n'
            # output += " [-] Type: %s\n" % self.Type
            # output += " [-] Encoding: %s\n" % self.Encoding
            output += " [-] Print Name: %s\n" % self.PrintName
            # output += " [-] Alias: %s\n" % self.Alias
            # output += " [-] Subject: %s\n" % self.Subject
            # output += " [-] Issuer: %s\n" % self.Issuer
            # output += " [-] Serial Number: %s\n" % self.Serial_Number
            # output += " [-] Subject Key Identifier: %s\n" % self.Subject_Key_Identifier
            # output += " [-] Public Key Hash: %s\n" % self.Public_Key_Hash
            output += " [-] Certificate: %s\n" % base64.b64encode(self.Certificate)
            return output

        @property
        def exportable(self):
            return self.Certificate

        @property
        def FileName(self):
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self):
            return '.crt'

    class SSGBEncryptedRecord(KeychainRecord):
        def __init__(self):
            self._password = None
            self.locked = True
            self.password_b64_encoded = False

            Chainbreaker.KeychainRecord.__init__(self)

        def decrypt_password(self):
            try:
                if self.SSGP and self.DBKey:
                    self._password = Chainbreaker._kcdecrypt(self.DBKey, self.SSGP.IV, self.SSGP.EncryptedPassword)
                    if not all(c in string.printable for c in self._password):
                        self._password = base64.b64encode(self._password)
                        self.password_b64_encoded = True
                    self.locked = False
            except KeyError:
                if not self._password:
                    self.locked = True
                    self._password = None
            return self._password

        def get_password_output_str(self):
            password = self.Password
            if self.password_b64_encoded:
                return ' [-] Base64 Encoded Password: {}\n'.format(password)
            else:
                return ' [-] Password: {}\n'.format(password)

        @property
        def Password(self):
            if not self._password:
                self.decrypt_password()
                if self.locked:
                    self._password = Chainbreaker.KEYCHAIN_LOCKED_SIGNATURE

            return self._password

        @property
        def exportable(self):
            return self.__str__()

        @property
        def FileName(self):
            return "".join(x for x in self.PrintName if x.isalnum())

        @property
        def FileExt(self):
            return '.txt'

    class GenericPasswordRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None, creator=None, type=None, print_name=None,
                     alias=None, account=None, service=None, key=None, ssgp=None, dbkey=None):
            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name
            self.Alias = alias
            self.Account = account
            self.Service = service
            self.Key = key
            self.SSGP = ssgp
            self.DBKey = dbkey

            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self):
            output = '[+] Generic Password Record\n'
            output += ' [-] Create DateTime: %s\n' % self.Created  # 16byte string
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified  # 16byte string
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Creator: %s\n' % self.Creator
            output += ' [-] Type: %s\n' % self.Type
            output += ' [-] Print Name: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] Service: %s\n' % self.Service
            output += self.get_password_output_str()

            return output

    class InternetPasswordRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None, comment=None, creator=None, type=None,
                     print_name=None, alias=None, protected=None, account=None, security_domain=None, server=None,
                     protocol_type=None, auth_type=None, port=None, path=None, ssgp=None, dbkey=None):

            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Comment = comment
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name
            self.Alias = alias
            self.Protected = protected
            self.Account = account
            self.SecurityDomain = security_domain
            self.Server = server
            self.ProtocolType = protocol_type
            self.AuthType = auth_type
            self.Port = port
            self.Path = path
            self.SSGP = ssgp
            self.DBKey = dbkey

            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self):
            output = '[+] Internet Record\n'
            output += ' [-] Create DateTime: %s\n' % self.Created
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Comment: %s\n' % self.Comment
            output += ' [-] Creator: %s\n' % self.Creator
            output += ' [-] Type: %s\n' % self.Type
            output += ' [-] PrintName: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Protected: %s\n' % self.Protected
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] SecurityDomain: %s\n' % self.SecurityDomain
            output += ' [-] Server: %s\n' % self.Server

            try:
                output += ' [-] Protocol Type: %s\n' % PROTOCOL_TYPE[self.ProtocolType]
            except KeyError:
                output += ' [-] Protocol Type: %s\n' % self.ProtocolType

            try:
                output += ' [-] Auth Type: %s\n' % AUTH_TYPE[self.AuthType]
            except KeyError:
                output += ' [-] Auth Type: %s\n' % self.AuthType

            output += ' [-] Port: %d\n' % self.Port
            output += ' [-] Path: %s\n' % self.Path
            output += self.get_password_output_str()

            return output

    class AppleshareRecord(SSGBEncryptedRecord):
        def __init__(self, created=None, last_modified=None, description=None, comment=None, creator=None, type=None,
                     print_name=None, alias=None, protected=None, account=None, volume=None, server=None,
                     protocol_type=None, address=None, signature=None, dbkey=None, ssgp=None):
            self.Created = created
            self.LastModified = last_modified
            self.Description = description
            self.Comment = comment
            self.Creator = creator
            self.Type = type
            self.PrintName = print_name
            self.Alias = alias
            self.Protected = protected
            self.Account = account
            self.Volume = volume
            self.Server = server
            self.Protocol_Type = protocol_type
            self.Address = address
            self.Signature = signature
            self.SSGP = ssgp
            self.DBKey = dbkey

            Chainbreaker.SSGBEncryptedRecord.__init__(self)

        def __str__(self):
            output = '[+] AppleShare Record (no longer used in OS X)\n'
            output += ' [-] Create DateTime: %s\n' % self.Created
            output += ' [-] Last Modified DateTime: %s\n' % self.LastModified
            output += ' [-] Description: %s\n' % self.Description
            output += ' [-] Comment: %s\n' % self.Comment
            output += ' [-] Creator: %s\n' % self.Creator
            output += ' [-] Type: %s\n' % self.Type
            output += ' [-] PrintName: %s\n' % self.PrintName
            output += ' [-] Alias: %s\n' % self.Alias
            output += ' [-] Protected: %s\n' % self.Protected
            output += ' [-] Account: %s\n' % self.Account
            output += ' [-] Volume: %s\n' % self.Volume
            output += ' [-] Server: %s\n' % self.Server

            try:
                output += ' [-] Protocol Type: %s\n' % PROTOCOL_TYPE[self.Protocol_Type]
            except KeyError:
                output += ' [-] Protocol Type: %s\n' % self.Protocol_Type

            output += ' [-] Address: %d\n' % self.Address
            output += ' [-] Signature: %s\n' % self.Signature
            output += self.get_password_output_str()

            return output


if __name__ == "__main__":
    import argparse
    import getpass
    import sys
    import os
    import datetime
    import hashlib

    arguments = argparse.ArgumentParser(description='Dump items stored in an OSX Keychain')

    # General Arguments
    arguments.add_argument('keychain', help='Location of the keychain file to parse')

    # Available actions
    dump_actions = arguments.add_argument_group('Dump Actions')
    dump_actions.add_argument('--dump-all', '-a', help='Dump records to the console window.',
                              action='store_const', dest='dump_all', const=True)
    dump_actions.add_argument('--dump-keychain-password-hash',
                              help='Dump the keychain password hash in a format suitable for hashcat or John The Ripper',
                              action='store_const', dest='dump_keychain_password_hash', const=True)
    dump_actions.add_argument('--dump-generic-passwords', help='Dump all generic passwords',
                              action='store_const', dest='dump_generic_passwords', const=True)
    dump_actions.add_argument('--dump-internet-passwords', help='Dump all internet passwords',
                              action='store_const', dest='dump_internet_passwords', const=True)
    dump_actions.add_argument('--dump-appleshare-passwords', help='Dump all appleshare passwords',
                              action='store_const', dest='dump_appleshare_passwords', const=True)
    dump_actions.add_argument('--dump-private-keys', help='Dump all private keys',
                              action='store_const', dest='dump_private_keys', const=True)
    dump_actions.add_argument('--dump-public-keys', help='Dump all public keys',
                              action='store_const', dest='dump_public_keys', const=True)
    dump_actions.add_argument('--dump-x509-certificates', help='Dump all X509 certificates',
                              action='store_const', dest='dump_x509_certificates', const=True)

    # Export private keys, public keys, or x509 certificates to disk.
    export_actions = arguments.add_argument_group('Export Actions',
                                                  description='Export records to files. Save location '
                                                              'is CWD, but can be overridden with --output / -o')

    export_actions.add_argument('--export-keychain-password-hash', help='Save the keychain password hash to disk',
                                action='store_const', dest='export_keychain_password_hash', const=True)
    export_actions.add_argument('--export-generic-passwords', help='Save all generic passwords to disk',
                                action='store_const', dest='export_generic_passwords', const=True)
    export_actions.add_argument('--export-internet-passwords', help='Save all internet passwords to disk',
                                action='store_const', dest='export_internet_passwords', const=True)
    export_actions.add_argument('--export-appleshare-passwords', help='Save all appleshare passwords to disk',
                                action='store_const', dest='export_appleshare_passwords', const=True)
    export_actions.add_argument('--export-private-keys', help='Save private keys to disk',
                                action='store_const', dest='export_private_keys', const=True)
    export_actions.add_argument('--export-public-keys', help='Save public keys to disk',
                                action='store_const', dest='export_public_keys', const=True)
    export_actions.add_argument('--export-x509-certificates', help='Save X509 certificates to disk',
                                action='store_const', dest='export_x509_certificates', const=True)
    export_actions.add_argument('--export-all', '-e',
                                help='Save records to disk',
                                action='store_const', dest='export_all', const=True)

    misc_actions = arguments.add_argument_group('Misc. Actions')

    misc_actions.add_argument('--check-unlock-options', '-c',
                              help='Only check to see if the provided unlock options work.'
                                   ' Exits 0 on success, 1 on failure.',
                              action='store_const', dest='check_unlock', const=True)

    # Keychain Unlocking Arguments
    unlock_args = arguments.add_argument_group('Unlock Options')
    unlock_args.add_argument('--password-prompt', '-p', help='Prompt for a password to use in unlocking the keychain',
                             action='store_const', dest='password_prompt', const=True)
    unlock_args.add_argument('--password', help='Unlock the keychain with a password, provided on the terminal.'
                                                'Caution: This is insecure and you should likely use'
                                                '--password-prompt instead')
    unlock_args.add_argument('--key-prompt', '-k', help='Prompt for a key to use in unlocking the keychain',
                             action='store_const', dest='key_prompt', const=True)
    unlock_args.add_argument('--key', help='Unlock the keychain with a key, provided via argument.'
                                           'Caution: This is insecure and you should likely use --key-prompt instead')
    unlock_args.add_argument('--unlock-file', help='Unlock the keychain with a key file')

    # Output arguments
    output_args = arguments.add_argument_group('Output Options')
    output_args.add_argument('--output', '-o', help='Directory to output exported records to.')
    output_args.add_argument('-d', '--debug', help="Print debug information", action="store_const", dest="loglevel",
                             const=logging.DEBUG)

    arguments.set_defaults(
        loglevel=logging.INFO,
        dump_all=False,
        dump_keychain_password_hash=False,
        dump_generic_passwords=False,
        dump_internet_passwords=False,
        dump_appleshare_passwords=False,
        dump_private_keys=False,
        dump_public_keys=False,
        dump_x509_certificates=False,
        export_keychain_password_hash=False,
        export_generic_passwords=False,
        export_internet_passwords=False,
        export_appleshare_passwords=False,
        export_private_keys=False,
        export_public_keys=False,
        export_x509_certificates=False,
        export_all=False,
        check_unlock=False,
        password_prompt=False,
        key_prompt=False,
        password=None,
        key=None,
        unlock_file=None,
    )

    args = arguments.parse_args()

    if args.password_prompt:
        args.password = getpass.getpass('Unlock Password: ')

    if args.key_prompt:
        args.key = getpass.getpass('Unlock Key: ')

    # create logger
    logging.basicConfig(format='%(asctime)s - %(levelname)s - %(message)s',
                        level=args.loglevel,
                        stream=sys.stdout)

    logger = logging.getLogger('Chainbreaker')

    if args.output:
        if not os.path.exists(args.output):
            try:
                os.makedirs(args.output)
            except OSError as e:
                logger.critical("Unable to create output directory: %s" % args.output)
                exit(1)
        logger.addHandler(logging.FileHandler(os.path.join(args.output, 'output.log'), mode='w'))
    else:
        args.output = os.getcwd()

    # If dump-all or export-all is set, set the individual args
    if args.dump_all:
        args.dump_keychain_password_hash = args.dump_generic_passwords = args.dump_internet_passwords = \
            args.dump_appleshare_passwords = args.dump_public_keys = args.dump_private_keys = \
            args.dump_x509_certificates = True

    if args.export_all:
        args.export_keychain_password_hash = args.export_generic_passwords = args.export_internet_passwords = \
            args.export_appleshare_passwords = args.export_public_keys = args.export_private_keys = \
            args.export_x509_certificates = True

    # Make sure we're actually doing something, exit if we're not.
    if not (args.dump_keychain_password_hash or args.dump_generic_passwords or args.dump_internet_passwords \
            or args.dump_appleshare_passwords or args.dump_public_keys or args.dump_private_keys or \
            args.dump_x509_certificates or args.export_keychain_password_hash or \
            args.export_generic_passwords or args.export_internet_passwords \
            or args.export_appleshare_passwords or args.export_private_keys or args.export_public_keys or \
            args.export_x509_certificates or args.dump_all or args.export_all or args.check_unlock):
        logger.critical("No action specified.")
        exit(1)

    # Calculate the MD5 and SHA256 of the input keychain file.
    keychain_md5 = hashlib.md5(args.keychain).hexdigest()
    keychain_sha256 = hashlib.sha256(args.keychain).hexdigest()

    # Print out some summary info before we actually start doing any work.
    summary_output = [
        "\n\nChainBreaker 2 - https://github.com/gaddie-3/chainbreaker\n",
        "Runtime Command: %s" % ' '.join(sys.argv),
        "Keychain: %s" % args.keychain,
        "Keychain MD5: %s" % keychain_md5,
        "Keychain 256: %s" % keychain_sha256,
        "Dump Start: %s" % datetime.datetime.now(),
    ]

    for line in summary_output:
        logger.info(line)

    summary_output.append("Dump Summary:")

    # Done parsing out input options, now actually do the work.
    keychain = Chainbreaker(args.keychain, unlock_password=args.password, unlock_key=args.key,
                            unlock_file=args.unlock_file)

    if args.check_unlock:
        if keychain.locked:
            logger.info("Invalid Unlock Options")
            exit(1)
        else:
            logger.info("Keychain Unlock Successful.")
            exit(0)

    output = []

    if args.dump_keychain_password_hash or args.export_keychain_password_hash:
        output.append(
            {
                'header': 'Keychain Password Hash',
                'records': [keychain.dump_keychain_password_hash()],  # A little hackish, but whatever.
                'write_to_console': args.dump_keychain_password_hash,
                'write_to_disk': args.export_keychain_password_hash,
                'write_directory': os.path.join(args.output)
            }
        )

    if args.dump_generic_passwords or args.export_generic_passwords:
        output.append(
            {
                'header': 'Generic Passwords',
                'records': keychain.dump_generic_passwords(),
                'write_to_console': args.dump_generic_passwords,
                'write_to_disk': args.export_generic_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'generic')
            }
        )
    if args.dump_internet_passwords or args.export_internet_passwords:
        output.append(
            {
                'header': 'Internet Passwords',
                'records': keychain.dump_internet_passwords(),
                'write_to_console': args.dump_internet_passwords,
                'write_to_disk': args.export_internet_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'internet')
            }
        )
    if args.dump_appleshare_passwords or args.export_appleshare_passwords:
        output.append(
            {
                'header': 'Appleshare Passwords',
                'records': keychain.dump_appleshare_passwords(),
                'write_to_console': args.dump_appleshare_passwords,
                'write_to_disk': args.export_appleshare_passwords,
                'write_directory': os.path.join(args.output, 'passwords', 'appleshare')
            }
        )
    if args.dump_private_keys or args.export_private_keys:
        output.append(
            {
                'header': 'Private Keys',
                'records': keychain.dump_private_keys(),
                'write_to_console': args.dump_private_keys,
                'write_to_disk': args.export_private_keys,
                'write_directory': os.path.join(args.output, 'keys', 'private')
            }
        )
    if args.dump_public_keys or args.export_public_keys:
        output.append(
            {
                'header': 'Public Keys',
                'records': keychain.dump_public_keys(),
                'write_to_console': args.dump_public_keys,
                'write_to_disk': args.export_public_keys,
                'write_directory': os.path.join(args.output, 'keys', 'public')
            }
        )
    if args.dump_x509_certificates or args.export_x509_certificates:
        output.append(
            {
                'header': 'x509 Certificates',
                'records': keychain.dump_x509_certificates(),
                'write_to_console': args.dump_x509_certificates,
                'write_to_disk': args.export_x509_certificates,
                'write_directory': os.path.join(args.output, 'certificates')
            }
        )

    try:
        for record_collection in output:
            if 'records' in record_collection:
                number_records = len(record_collection['records'])
                collection_summary = "%s %s" % (len(record_collection['records']), record_collection['header'])
                logger.info(collection_summary)

                summary_output.append("\t%s" % collection_summary)

                for record in record_collection['records']:
                    if record_collection.get('write_to_console', False):
                        for line in str(record).split('\n'):
                            logger.info("\t%s" % line)
                    if record_collection.get('write_to_disk', False):
                        record.write_to_disk(record_collection.get('write_directory', args.output))
                    logger.info("")

        summary_output.append("Dump End: %s" % datetime.datetime.now())

        if any(x.get('write_to_disk', False) for x in output):
            with open(os.path.join(args.output, "summary.txt"), 'w') as summary_fp:
                for line in summary_output:
                    summary_fp.write("%s\n" % line)
                    logger.info(line)
        else:
            for line in summary_output:
                logger.info(line)

    except KeyboardInterrupt:
        exit(0)

    exit(0)

# Some great reading on the Keychain Format can be found here:
# https://repo.zenk-security.com/Forensic/Keychain%20Analysis%20with%20Mac%20OS%20X%20Memory%20Forensics.pdf
