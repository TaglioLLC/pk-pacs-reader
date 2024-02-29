## Introduction 

This software implements the PK-PACS specification in Python using a USB contactless smartcard reader.  This code is provided as-is and is intended
to be used as a reference implementation.  Questions and comments about this software should be directed to `pkpacs@taglio.com`.

The PK-PACS specification can be found here:
https://github.com/TaglioLLC/pk-pacs-spec 


## Setup 

You will need to have the following in order to run this utility:

- A machine running Windows 8 or greater, or Linux (e.g. Ubuntu 22.04 LTS). 
- Python version 3.6 or greater, or version 3.11 or less.  We recommend version 3.11 if you're installing Python for the first time.  You can download version 3.11 [here](https://www.python.org/downloads/).
- A USB contactless card reader that supports ISO/IEC 14443 such as [this](https://www.identiv.com/products/logical-access-control/smart-card-readers-writers/contactless-smart-card-readers-writers/3700f).
- The reader needs to be plugged into a USB port on the machine.  Windows has built-in drivers for CCID compatible readers. 
- A smartcard that implements the PK-PACS standard. (If you need a test card, contact Taglio at `pkpacs@taglio.com`). 

Before running the utility, you need to install the required packages.  If you are using Windows, this can be done by double-clicking on the `install_requirements.py` script.  If you are using Linux, please follow the directions in the next section.   


## Linux installation

(Please skip to the next section if you are using Windows.)  Execute the following steps to install the required software:

```
sudo apt install swig
sudo apt install libpcsclite-dev
sudo apt install pcsc-tools
sudo apt install pcscd
sudo apt install libccid
sudo apt install libnss3-tools
```

Then install the required Python packages by running:

`python3 install_requirements.py`


## Running

Double-clicking on pkpacs.py (Windows) or running `python3 pkpacs.py` (Linux) will run the PK-PACS utility in its *identifier* mode (this is the default mode without any command-line arguments), which will print the ID-OID value of the PK-PACS card presented, according to the `pkpacs_config.json` configuration file.

Or you run can the `pkpacs.py` utility with the following command-line arguments:

- **-config**  This argument specifies an alternate configuration file or path.  For example, you could specify `-config c:\some_path` and it will look for `pkpacs_config.json`
in the `c:\some_path` directory.  Or you could specify `-config c:\some_path\my_config.json` and it will use the specified configuration file.  By default `pkpacs.py` will look
in the same directory for `pkpacs_config.json`
- **-test**  This argument is a test mode that reads out information on the PK-PACS card presented.
- **-copy_keys**  This will instruct the utlity to extract the public keys from the certificates in the PK-TrustCert Path and write them as `.pem` file into the PK-TrustKey Path. 
- **-verbose**  This is useful for debugging, etc. 

If you're using Windows, running the utlity from the command-line can be done from a command prompt (e.g. `cmd`).  Within `cmd` you can run `py`, which should be within the PATH to run Python.  So for example, after changing directories into the directory containing `pkpacs.py`, you can run:

`py pkpacs.py -test -verbose` 

If you're using Linux, running this utility from the command-line is recommended.  Typically, `python3` is pointing to a compatible version of Python:

`python3 pkpacs.py -test -verbose`


## Configuration

The configuration of the utility is contained in the `pkpacs_config.json` file, which is located in the same directory as `pkpacs.py` by default.  The file contains 
the following configuration fields:

- **PK-TrustKey Path**  This value is a string that specifies the path of the PK-TrustKeys, which should be in `.pem` format.  The path can either be relative to 
the directory that `pkpacs.py` is located in, or it can be an absolute path.  For example `"c:\\some_path"`.  (Note, the use of double backslashes to indicate a backslash within a 
string literal.)  
- **PK-TrustCert Path** This value is a string that specifies the path of the PK-TrustCertificates, which can be in `.pem`, `.crt` , or `.cer` format.  The path can either 
be relative to directory that `pkpacs.py` is located in, or it can be an absolute path.  For example `"c:\\some_path"`.  (Note, the use of double backslashes to indicate a
backslash) within a string literal.
- **Keys**  This is a list that specifies the order of public keys to try when validating the signature on a PK-PACS card.  Each key should be in `.pem` format.
Each entry in the list looks like:
`{"<key label>", "<absolute file path to key or relative to Certificate Path>"}`.  So for example, here is a possible list of keys containing relative paths to the PK-TrustKey Path or absolute paths:
```
"Keys": [
    {"key1": "pkpacs_root.pem"},
    {"key2": "pkpacs_demo.pem"},
    {"key3": "c:\\demo_keys\\demo_cert.pem"}
],
```
- **Priority List**  A list of of validation combinations goes here.  This specifies the ID-OID value that gets printed to the console if the PK-PACS card is verified
(both a challenge verification is successful and the signature is verified using the one of the keys listed in the `Keys` field).  If the first ID-OID in the Priority List isn't contained in the card, the second ID-OID in the Priority List is used, and so on.  If none of the ID-OID are present or the card fails during verification, no value is printed to the console.  The Priority List is in the following format:
`["<key label from Keys>", "<ID-OID">, "<output format: UUID, HEX, or ASCII>"]` Note, if `<output format>` is not specified, it will look-up the preferred format
based on the ID-OID and use that format when printing. 
For example, here is a Priority list with both implied and specified formats:  
```
"Priority List": [
    ["key1", "44986.8.1"], 
    ["key1", "44986.8.2", "HEX"], 
    ["key2", "59685.8.2", "HEX"]
],
```

## Keeping in touch

Questions and comments about this software should be directed to `pkpacs@taglio.com`.
