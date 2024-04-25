import time
import os
import io
import gzip
import hashlib
import glob
import json
import argparse
import uuid
import secrets
import base64
from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from pynput import keyboard
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

DEFAULT_CONFIG = {
    # Path to directory containing public keys for use as PK-TrustKeys.
    # "." means relative to current directory. The files in this directory
    # need to be PEM format and have .pem file extension.
    # For example:
    #
    # "c:\\keys" (backslashes need to be doubled)
    # or "c:/keys" (forward slashes instead of backslashes)
    # or "/etc/keys" (Linux or macOS)
    "PK-TrustKey Path": ".",
    # Path to directory containing certificates for use as PK-TrustCerts.
    # "." means relative to current directory. The files in this directory
    # can be .pem, .cer, or .crt format.
    # For example:
    #
    # "c:\\certs" (backslashes need to be doubled)
    # or "c:/certs" (forward slashes instead of backslashes)
    # or "/etc/certs" (Linux or macOS)
    "PK-TrustCert Path": ".",
    # A list of keys goes here in the following format:
    # {"<key label>", "<absolute file path to key or relative to PK-TrustKey Path>"}
    # For example:
    #
    # {"key1": "pkpacs_root.pem"},
    # {"key2": "pkpacs_demo.pem"},
    # {"key3": "c:\\demo_keys/demo_cert.pem"},
    # ...
    "Keys": [],
    # A list of validation combinations goes here in the following format:
    # ["<key label from Keys>", "<ID-OID">, "<output format: UUID, HEX, or ASCII>"]
    # Note, if <output format> is not specified, it will look up the preferred format
    # based on the ID_OID.
    # For example:
    #
    # ["key1", "44986.8.1"],
    # ["key1", "44986.8.2", "HEX"],
    # ["key2", "59685.8.2", "HEX"],
    # ...
    "Priority List": [],
}

DEFAULT_CONFIG_FILE = "pkpacs_config.json"
CRYPTO_LEN = 256
MAX_LEN = 255
CONTINUE_MASK = 0x6100
COPIED_KEY_TAG = "copied_key"
TYPE_PROTOCOL_VERSION = 0x61
AID_INSTANCE = bytes.fromhex("a00000030800001000") # application ID
SELECT = bytes.fromhex("00a4 0400 09") + AID_INSTANCE + bytes([0x00])
GET_DATA = bytes.fromhex("00cb 3fff 05 5c 03 5f c1 01") + bytes([0x00])
GET_RESPONSE = bytes.fromhex("00c0 0000")
CERTIFICATE_TYPES = ["pem", "cer", "crt"]
KEY_TYPES = ["pem"]
OID_PREFIX = "1.3.6.1.4.1."
ID_OID_PREFIXES = ["44986", "51432", "59685", "58268"]
ID_OID_SUFFIXES = {
    ".2.1.1": {"name": "Certificate for Authentication", "format": "HEX"},
    ".2.1.0": {"name": "Certificate for Digital Signature", "format": "HEX"},
    ".2.1.2": {"name": "Certificate for Key Management", "format": "HEX"},
    ".2.5.0": {"name": "Certificate for Card Authentication", "format": "HEX"},
    ".8.1": {"name": "PK-PACS UUID", "format": "UUID"},
    ".8.2": {"name": "PK-PACS NUID", "format": "HEX"},
    ".8.3": {"name": "PK-PACS UID", "format": "HEX"},
    ".8.8": {"name": "PK-PACS FAC/CSN", "format": "FAC/CSN"},
}
PKOC_TYPE_PROTOCOL_VERSION = 0x5c
PKOC_VERSION_0100 = b'\x01\x00'
PKOC_LEN_TX_ID = 0x10
PKOC_LEN_READER_ID = 0x20
PKOC_TYPE_TRANSACTION_IDENTIFIER = 0x4c
PKOC_TYPE_READER_IDENTIFIER = 0x4d
PKOC_AUTHENTICATE = bytes.fromhex('8080 0001 38')
PKOC_AID_INSTANCE = bytes.fromhex('a000000898000001') # PKOC application ID
PKOC_SELECT = bytes.fromhex("00a4 0400 08") + PKOC_AID_INSTANCE + bytes([0x00])
PKOC_TYPE_PUBKEY = 0x5a
PKOC_LEN_KEY = 0x20 
PKOC_LEN_PUBKEY = 1 + PKOC_LEN_KEY*2
PKOC_TYPE_SIGNATURE = 0x9e 
PKOC_LEN_SIGNATURE = PKOC_LEN_KEY*2
RETRIES = 10


# Priority List indexes
KEY_LABEL = 0
ID_OID = 1
FORMAT = 2


def find_tlv_tag(buffer, offset, tag, search_sub_tags):
    if buffer is None:
        return None

    while offset < len(buffer):
        temp_len = 0
        temp_offset = 0

        if buffer[offset + 1] == 0x82:
            if offset + 4 > len(buffer):
                return None
            temp_len = (buffer[offset + 2] << 8) | buffer[offset + 3]
            temp_offset = 4
        elif buffer[offset + 1] == 0x81:
            if offset + 3 > len(buffer):
                return None
            temp_len = buffer[offset + 2]
            temp_offset = 3
        else:
            if offset + 2 > len(buffer):
                return None
            temp_len = buffer[offset + 1]
            temp_offset = 2

        if buffer[offset] == tag:
            value = buffer[offset + temp_offset : offset + temp_offset + temp_len]
            return value
        else:
            if search_sub_tags:
                offset += temp_offset
            else:
                offset += temp_len + temp_offset

    return None


def parse_tlv(buf, ofs):
    t = buf[ofs]
    ofs += 1
    l = buf[ofs]
    ofs += 1
    v = buf[ofs:ofs + l]
    ofs += l
    return t, v, ofs


def build_tlv(tag, value):
    return bytes([tag, len(value)]) + value


def der_base64_encode(data):
    preamble = bytes.fromhex("3059301306072A8648CE3D020106082A8648CE3D030107034200")
    data = preamble + data
    return base64.b64encode(data).decode()

class PKPACS:
    """Implements PK-PACS specification in https://github.com/TaglioLLC/pk-pacs-spec"""

    def __init__(self, config_path=".", verbose=False, copy_keys=False):
        """
        config_path: directory to look in for the config file "pkpacs_config.json" or the complete config file path.
        verbose: if True will print information mostly useful for debugging.
        copy_keys: if True will extract public keys from certificates in PK-TrustCert Path and write as .pem files into PK-TrustKey Path.
        """
        self.config_path = config_path
        self.verbose = verbose

        self.previous_card = None
        self.connection = None
        self._load_config()
        if copy_keys:
            self.copy_keys()

    def _load_config(self):
        self.config = DEFAULT_CONFIG
        if self.config_path.lower().endswith(".json"):
            self.config_file = self.config_path
        else:
            self.config_file = os.path.join(self.config_path, DEFAULT_CONFIG_FILE)

        try:
            with open(self.config_file) as f:
                config = json.load(f)
        except Exception as e:
            print(f"Unable to load config file {self.config_file}: {e}")
            config = {}

        # Update default values with values in config file.
        self.config.update(config)
        # Save new configuration if it's changed.
        if self.config != config:
            if self.verbose:
                print(f"Saving updated configuration to {self.config_file}...")
            self.save_config()
        if self.verbose:
            print(f"Configuration from {self.config_file}:")
            print(self.config)

    def save_config(self):
        try:
            with open(self.config_file, "w") as f:
                json.dump(self.config, f, indent=4)
        except Exception as e:
            print(f"Unable to save config file {self.config_file}: {e}")

    def _get_certificates(self):
        # Get a list of all trust certificate files in the certificate path.
        wildcards = [f"*.{c_type}" for c_type in CERTIFICATE_TYPES]
        wildcards += [f"*/*.{c_type}" for c_type in CERTIFICATE_TYPES]
        certificates = [
            c
            for wildcard in wildcards
            for c in glob.glob(
                os.path.join(self.config["PK-TrustCert Path"], wildcard), recursive=True
            )
        ]
        certificates = [c for c in certificates if COPIED_KEY_TAG not in c]
        return certificates

    def _get_keys(self):
        wildcards = [f"*.{k_type}" for k_type in KEY_TYPES]
        wildcards += [f"*/*.{k_type}" for k_type in KEY_TYPES]
        keys = [
            k
            for wildcard in wildcards
            for k in glob.glob(
                os.path.join(self.config["PK-TrustKey Path"], wildcard), recursive=True
            )
        ]
        return keys

    def _load_certificates(self, certificate_filenames):
        certificates = {}

        for certificate_filename in certificate_filenames:
            if not certificate_filename.startswith(
                self.config["PK-TrustCert Path"]
            ) and not os.path.isabs(certificate_filename):
                certificate_filename = os.path.join(
                    self.config["PK-TrustCert Path"], certificate_filename
                )
            if self.verbose:
                print(f"    Reading certificate {certificate_filename}")
            with open(certificate_filename, "rb") as file:
                certificate_data = file.read()
            # Parse the certificate data. load_pem_x509_certificate() works with .pem, .cer, and .crt files.
            try:
                certificates[os.path.basename(certificate_filename)] = (
                    x509.load_pem_x509_certificate(certificate_data, default_backend())
                )
            except Exception as e:
                if self.verbose:
                    print(
                        f"Error: unable to certificate key file {certificate_filename}."
                    )

        return certificates

    def _load_keys(self, key_filenames):
        keys = {}

        for key_filename in key_filenames:
            if not key_filename.startswith(
                self.config["PK-TrustKey Path"]
            ) and not os.path.isabs(key_filename):
                key_filename = os.path.join(
                    self.config["PK-TrustKey Path"], key_filename
                )
            if self.verbose:
                print(f"    Reading key {key_filename}")
            with open(key_filename, "rb") as file:
                key_data = file.read()
            # Parse the key data.
            try:
                keys[os.path.basename(key_filename)] = (
                    serialization.load_pem_public_key(
                        key_data, backend=default_backend()
                    )
                )
            except Exception as e:
                if self.verbose:
                    print(f"Error: unable to load key file {key_filename}.")

        return keys

    def copy_keys(self):
        print("Copying keys...")
        try:
            certificates = self._get_certificates()
            # It's possible PK-TrustCert Path and PK-TrustKey Path are the same.
            # If so, we want to remove the previously-copied keys.
            certificates = [c for c in certificates if COPIED_KEY_TAG not in c]
            certificates = self._load_certificates(certificates)

            # Go through the certificates, extract the public key and save them in the PK-TrustKey Path under an augmented filename.
            for filename, certificate in certificates.items():
                base = os.path.basename(filename)
                base, extension = os.path.splitext(base)
                if certificate:
                    key_filename = os.path.join(
                        self.config["PK-TrustKey Path"], f"{base}_{COPIED_KEY_TAG}.pem"
                    )
                    # Write public key as PEM file.
                    if self.verbose:
                        print(f"    Writing {key_filename}")
                    with open(key_filename, "wb") as key_file:
                        key_file.write(
                            certificate.public_key().public_bytes(
                                encoding=serialization.Encoding.PEM,
                                format=serialization.PublicFormat.SubjectPublicKeyInfo,
                            )
                        )

        except Exception as e:
            print(f"Error: {e}")

        print("done.")

    def _wait_for_card(self):
        reader_list = readers()
        if not reader_list:
            print("No readers found")
            return None
        while True:
            if self.connection is not None:
                self.connection.disconnect()
            try:
                reader = reader_list[0]
                self.connection = reader.createConnection()
                self.connection.connect()
                atr = self.connection.getATR()
                if atr != self.previous_card:
                    if self.verbose:
                        print("Card change detected")
                    self.previous_card = atr
                    time.sleep(1)
                    return True
            except Exception:
                # No card in the reader or connection error
                if self.previous_card is not None:
                    if self.verbose:
                        print("Card removed")
                    self.previous_card = None

            time.sleep(0.1)

    def _apdu(self, command, ignore_error=False):
        for i in range(RETRIES):
            try:
                resp, sw1, sw2 = self.connection.transmit(list(command))
                break
            except CardConnectionException:
                print("Retrying...")
                pass
        if i == RETRIES - 1:
            raise RuntimeError("Error: Unable to communicate with card.")

        if sw1 != 0x90 or sw2 != 0x00:
            if not ignore_error:
                raise RuntimeError(f"Error: Invalid SW for the APDU: {command.hex()}")
        sw = (sw1 << 8) | sw2
        return bytes(resp), sw

    def get_pk_cert(self):
        # Send _apdus to get certificate.
        type_encoded, _ = self._apdu(SELECT)
        if type_encoded[0]!=TYPE_PROTOCOL_VERSION:
            return None
        cert, status = self._apdu(GET_DATA, True)
        while (status & CONTINUE_MASK) == CONTINUE_MASK:
            length = status & 0xFF
            data, status = self._apdu(GET_RESPONSE + bytes([length]), True)
            cert += data

        # Get length of certificate and remove header.
        cert_len = (cert[6] << 8) | cert[7]
        cert = cert[8 : 8 + cert_len]

        # Unzip using gzip.
        with io.BytesIO(cert) as byte_stream:
            # Open the BytesIO object with gzip to decompress it
            with gzip.open(byte_stream, "rb") as gzip_file:
                # Read the decompressed data
                cert_uncompressed = gzip_file.read()

        # Parse x509 certificate and return
        certificate = x509.load_der_x509_certificate(
            cert_uncompressed, default_backend()
        )
        return certificate

    def verify_challenge(self, certificate):
        # First create a challenge.  This is just some random data that's hashed (SHA256).
        data_to_sign = secrets.token_bytes(CRYPTO_LEN)
        hash_object = hashlib.sha256()
        hash_object.update(data_to_sign)
        challenge = hash_object.digest()

        # Pad the challenge hash according to PKCS #1 v1.5. Note, the card won't respond to data that isn't correctly padded.
        # Start by encoding hash with DER data based on hashing algorithm used.  See https://www.rfc-editor.org/rfc/rfc8017#page-47.
        der_challenge = (
            bytes.fromhex("30 31 30 0d 06 09 60 86 48 01 65 03 04 02 01 05 00 04 20")
            + challenge
        )  # SHA256 hash
        # Add additional padding according to https://www.rfc-editor.org/rfc/rfc8017#page-46.
        padded_challenge = (
            bytes([0x00, 0x01])
            + bytes([0xFF]) * (CRYPTO_LEN - 3 - len(der_challenge))
            + bytes([0x00])
            + der_challenge
        )

        # Send the first chunk of the challenge. We can only send 255 (MAX_LEN) bytes at a time.
        _apdudata = bytes.fromhex("7c820106820081820100") + padded_challenge
        data, status = self._apdu(
            bytes.fromhex("1087079eff") + _apdudata[:MAX_LEN], True
        )
        # Send remaining chunk and get the response, which contains the signature.
        chunk = _apdudata[MAX_LEN:]
        response, status = self._apdu(
            bytes.fromhex("0087079e") + bytes([len(chunk)]) + chunk + bytes([0]), True
        )
        while (status & CONTINUE_MASK) == CONTINUE_MASK:
            length = status & 0xFF
            data, status = self._apdu(GET_RESPONSE + bytes([length]), True)
            response += data

        # Parse response to get signature.
        val = find_tlv_tag(response, 0, 0x7C, False)
        if val is None:
            raise RuntimeError("Error: Invalid header")
        signature = find_tlv_tag(val, 0, 0x82, False)
        if signature is None:
            raise RuntimeError("Error: Unable to extract signature.")

        # Verify the signature of the challenge.
        try:
            # verify() will raise an InvalidSignature exception upon failure.
            certificate.public_key().verify(
                signature, data_to_sign, padding.PKCS1v15(), hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False

    def verify_certificate(self, certificate, trust_keys, trust_certificates=[]):
        result = False

        # Generate a dictionary of parsed keys.
        keys = self._load_keys(trust_keys)

        # Try to verify the signature with each trust key.
        # Create a dictionary of results: True if success, False if fail.
        for name, key in keys.items():
            try:
                # verify() will raise an InvalidSignature exception upon failure.
                key.verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
                result = True
                keys[name] = True
            except InvalidSignature:
                keys[name] = False

        # Generate a dictionary of parsed certificates.
        certificates = self._load_certificates(trust_certificates)

        # Try to verify the signature with each trust certificate.
        # Create a dictionary of results: True if success, False if fail.
        for name, cert in certificates.items():
            try:
                # verify() will raise an InvalidSignature exception upon failure.
                cert.public_key().verify(
                    certificate.signature,
                    certificate.tbs_certificate_bytes,
                    padding.PKCS1v15(),
                    certificate.signature_hash_algorithm,
                )
                result = True
                certificates[name] = True
            except InvalidSignature:
                certificates[name] = False

        # Return True if verify works with one or more certificates.
        # And return the dictionary of all key and certificate results.
        return result, {**keys, **certificates}

    def print_oid(self, oid):
        # Print ID-OIDs that are associated with PK-PACS.
        prefixes = [OID_PREFIX + p for p in ID_OID_PREFIXES]
        if any([oid.oid.dotted_string.startswith(p) for p in prefixes]):
            for suffix, val in ID_OID_SUFFIXES.items():
                if oid.oid.dotted_string.endswith(suffix):
                    print(
                        f"ID_OID: {oid.oid.dotted_string.replace(OID_PREFIX, '')}, {val['name']}: {self.format_data(oid.value.public_bytes(), val['format'])}"
                    )
        elif self.verbose:
            print(
                f"OID: {oid.oid.dotted_string}, length: {len(oid.value.public_bytes())}, contents: (0x){oid.value.public_bytes().hex()}"
            )

    def _q_check(self, key):
        try:
            if key.char == "q":
                print("Exiting...")
                os._exit(0)
        except AttributeError:
            pass

    def _find_key(self, key_label):
        for key in self.config["Keys"]:
            for k, filename in key.items():
                if k == key_label:
                    return filename
        raise RuntimeError(f'Error: cannot find key label "{key_label}" in Keys list.')

    def format_data(
        self,
        data,
        format_,
    ):
        format_ = format_.upper()
        # Since data is typically ASN.1 octets, we typically toss the first two bytes.
        if format_ == "UUID":
            if len(data) < 18:
                raise RuntimeError(f"Error: UUID has {len(data)} bytes (needs 18).")
            return "(0x)"+str(uuid.UUID(bytes=data[2:]))
        elif format_ == "HEX":
            return "(0x)"+data[2:].hex()
        elif format_ == "ASCII":
            return data[2:].decode("ascii", "ignore")
        elif format_ == "FAC/CSN":
            string = data[2:].decode("ascii", "ignore")
            try:
                return f"FAC={int(string[:7])} CSN={int(string[7:])}"
            except:
                return string 
        else:
            raise RuntimeError(f'Error: format "{format_}" is not recogized.')

    def _extract_cn(self, string):
        try:
            # Split the string into key-value pairs
            pairs = string.split(",")
            # Iterate through each pair
            for pair in pairs:
                # Check if the pair starts with 'CN='
                if pair.startswith("CN="):
                    # Return the value part by removing the 'CN=' part
                    return pair[3:]
        except:
            pass 

        return string


    def run_test(self, certificate):
        print(f"Issuer: {self._extract_cn(certificate.issuer.rfc4514_string())}")
        print(f"Subject: {self._extract_cn(certificate.subject.rfc4514_string())}")
        for id_oid in certificate.extensions:
            self.print_oid(id_oid)

        # Verify PK-Cert with a challenge.
        print("Verifying card with challenge...")
        print("Succeeded!") if self.verify_challenge(certificate) else print("Failed")

        # Verify PK-Cert signature with PK-TrustKey.
        print("Verifying PK-Cert signature with PK-TrustKeys and/or PK-TrustCerts...")
        result, results = self.verify_certificate(
            certificate, self._get_keys(), self._get_certificates()
        )
        for name, success in results.items():
            print(f"    {name}: {'succeeded' if success else 'failed'}")
        print("Succeeded!") if result else print("Failed")

    def run_validate(self, certificate):
        # Run through Priority List.
        for item in self.config["Priority List"]:
            if self.verbose:
                print(f"Trying {item}...")
            for oid in certificate.extensions:
                trust_key = self._find_key(item[KEY_LABEL])
                if oid.oid.dotted_string.endswith(item[ID_OID]):
                    if self.verbose:
                        print(f"Found ID_OID {item[ID_OID]}")
                    # Verify PK-Cert with a challenge.
                    if self.verify_challenge(certificate):
                        if self.verbose:
                            print(f"Challenge verification succeeded.")
                        # Verify PK-Cert signature with PK-TrustKey.
                        result, _ = self.verify_certificate(certificate, [trust_key])
                        if result:
                            # If format isn't specified, see if we can look it up in the ID_OID_SUFFIXES and see which format
                            # we should use. If that doesn't work, just use HEX.
                            suffix = oid.oid.dotted_string.replace(OID_PREFIX, "")
                            for s in ID_OID_PREFIXES:
                                suffix = suffix.replace(s, "")
                            try:
                                format_ = (
                                    item[FORMAT]
                                    if len(item) >= 3
                                    else ID_OID_SUFFIXES[suffix]["format"]
                                )
                            except KeyError:
                                format_ = "HEX"
                            print(self.format_data(oid.value.public_bytes(), format_))
                            return
                        elif self.verbose:
                            print(
                                "PK-Cert signature verification with PK-TrustKey failed."
                            )
                    elif self.verbose:
                        print("Challenge verification of the card failed.")

    def run_pkoc_validate(self):
        if self.verbose:
            print("\nAttempting to read PKOC credentials...")
        
        # Select PKOC, see if it succeeds
        type_encoded, _ = self._apdu(PKOC_SELECT)
        type_, version, _ = parse_tlv(type_encoded, 0)
        if type_!=PKOC_TYPE_PROTOCOL_VERSION or version!=PKOC_VERSION_0100:
            if self.verbose:
                print("Wrong type")
            return None, None

        # Construct challenge and send
        tx_id = secrets.token_bytes(PKOC_LEN_TX_ID)
        reader_id = secrets.token_bytes(PKOC_LEN_READER_ID)
        tlv_version = build_tlv(PKOC_TYPE_PROTOCOL_VERSION, PKOC_VERSION_0100)
        tlv_tx_id = build_tlv(PKOC_TYPE_TRANSACTION_IDENTIFIER, tx_id)
        tlv_reader_id = build_tlv(PKOC_TYPE_READER_IDENTIFIER, reader_id)
        resp, _ = self._apdu(PKOC_AUTHENTICATE + tlv_version + tlv_tx_id + tlv_reader_id)

        # Parse response, extract public key and signature
        q_x = None
        q_y = None
        sign_raw = None
        ofs = 0
        while ofs < len(resp):
            type_, value, ofs = parse_tlv(resp, ofs)
            if type_==PKOC_TYPE_PUBKEY:
                if len(value) != PKOC_LEN_PUBKEY:
                    raise RuntimeError(f'Unexpected length of public key: {len(value):02x}')
                x_bytes = value[1:1 + PKOC_LEN_KEY]
                y_bytes = value[1 + PKOC_LEN_KEY:]
                full_key = value
                q_x = int.from_bytes(x_bytes, byteorder='big', signed=False)
                q_y = int.from_bytes(y_bytes, byteorder='big', signed=False)
                continue
            elif type_ == PKOC_TYPE_SIGNATURE:
                if len(value) != PKOC_LEN_SIGNATURE:
                    raise RuntimeError(f'Unexpected length of signature: {len(value):02x}')
                sign_raw = value
                continue
            else:
                # ignore unknown type_
                continue

        if q_x is None or q_y is None or sign_raw is None:
            raise RuntimeError('Incomplete response to authenticate')

        # Construct public key
        pub_key = ec.EllipticCurvePublicNumbers(
            x=q_x,
            y=q_y,
            curve=ec.SECP256R1()
        ).public_key(default_backend())

        # DER encode signature
        r = int.from_bytes(sign_raw[:32], byteorder='big')
        s = int.from_bytes(sign_raw[32:], byteorder='big')
        signature = encode_dss_signature(r, s)

        # Try to verify
        try:
            pub_key.verify(
                signature,
                tx_id,
                ec.ECDSA(hashes.SHA256())
            )
            # We've successfully verified, print credentials in various formats
            if not self.verbose:
                print("")
            print("PKOC select and challenge verify succeeded! (credentials below)")
            print(f"    64-bit: (0x){x_bytes[-8:].hex()}")
            print(f"    256-bit: (0x){x_bytes.hex()}")
            print(f"    DER Base64: {der_base64_encode(full_key)}")
        except InvalidSignature:
            if self.verbose:
                print("PKOC select succeeded, challenge verify failed.")
            return None, None
        return q_x, q_y

    def run_loop(self, test):
        # Run "listener" for q keypress.
        print("Waiting for card... (Press q to quit.)")
        self.q_pressed = False
        listener = keyboard.Listener(on_press=self._q_check)
        listener.start()

        # Run main loop.
        while True:
            try:
                # Wait for card...
                if self._wait_for_card() is None:
                    break

                # Verify PK-Cert with a challenge.
                certificate = self.get_pk_cert()
                if test:
                    self.run_test(certificate)
                else:
                    self.run_validate(certificate)

            except Exception as e:
                if self.verbose:
                    print(f"An exception ocurred: {e}")
                print(f"This doesn't appear to be a valid PK-PACS card.")
            # Try PKOC if we're in test mode
            if test:
                try:
                    x, y = self.run_pkoc_validate()
                    if x is None and y is None:
                        raise RuntimeError() # Print message below
                except Exception as e:
                    if self.verbose:
                        print(f"An exception ocurred: {e}")
                        print(f"This doesn't appear to be a valid PKOC card.")


def main():
    # Create the command line parser
    parser = argparse.ArgumentParser(description="PK-PACS demo")

    # Add arguments
    parser.add_argument(
        "-config", help="Path to the configuration file (JSON format)", default="."
    )
    parser.add_argument("-test", help="Enable test mode", action="store_true")
    parser.add_argument(
        "-copy_keys",
        help="Extract public keys from certificates in PK-TrustCert Path and write as .pem files into PK-TrustKey Path",
        action="store_true",
    )
    parser.add_argument("-verbose", help="Verbose mode", action="store_true")

    # Parse the arguments
    args = parser.parse_args()

    pkpacs = PKPACS(args.config, verbose=args.verbose, copy_keys=args.copy_keys)
    pkpacs.run_loop(args.test)


if __name__ == "__main__":
    main()
