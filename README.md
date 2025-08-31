# vmk2rk
A tool developped with anything but a brain. You could use it to retrieve a BitLocker Recovery Password or any other Key Protector by providing a VMK and the targeted filesystem.

## Usage
Start by building it : 
```bash
cargo build -r 
```
Then simply provide a `VMK` and a `block/disk image file path` or the Recovery Password's `nonce`, `MAC` and `paylaod`. 
```
Usage: vmk2rk [OPTIONS] --vmk <Key>

Options:
  -v, --vmk <Key>
          VMK, key used to decrypt key protectors
  -n, --nonce <Nonce>
          Nonce used to decrypt the Recovery Password
  -m, --mac <MAC>
          MAC used to decrypt the Recovery Password
  -p, --payload <Payload>
          Payload containing the encrypted Recovery Password
  -d, --disk <DISKPATH>
          Disk from which Key Protectors are retrieved 
  -b, --bek
          Create BEK (BitLocker External Key) file if the Key Protector is configured on the provided disk
  -h, --help
          Print help (see a summary with '-h')
  -V, --version
          Print version
```

## How it works
![disk-parsing](./img/disk-parsing.png)
If the VMK, nonce, MAC and payload or provided when executing `vmk2rk`, it will proceed with decryption. However, if a block file or a disk image is provided, it will try to retrieve Key Protectors' nonce, MAC and  encrypted form :
1. The binary will read the GUID Partition Table (gpt) to retrieve the start address for each partition
2. It will try to identify the first encrypted partition
3. If found, it will read the volume header to retrieve the FVE metadata blocks addresses
4. The tool will then parse the key protectors and identify the one holding the encrypted Key Protector
5. The nonce, MAC and encrypted Key Protector will be extracted and passed to the decryption function

For a Recovery Password, the decryption process is as follows: 
- The payload is decrypted using AES-256-CCM
- The header describing the recovery password is removed and the rest is split into 8 2 bytes words
- The endianess for each word is swapped
- The words are then multiplied by `0x0b`
- The words are transformed into integers and displayed with `-` as separators
Other Key Protectors are stored in the FVE Metadata encrypted using AES-256-CCM.

## Supported Key Protectors 
- Recovery Passwords 
- Startup Keys

## How to get there 
To retrieve key protectors, it is required to gain access to one of them such as a VMK. This may be achieved by performing TPM sniffing. 

## What is possible with Recovery Passwords and Startup Keys
Upon successfully retrieving a Recovery Password or a Startup Key, it is possible to boot the disk on any machine even if PCR validation fails.

## Dependencies 
- [clap](https://docs.rs/clap/latest/clap/)
- [aes](https://docs.rs/aes/latest/aes/)
- [ccm](https://docs.rs/ccm/latest/ccm/)
- [gpt](https://docs.rs/gpt/latest/gpt/)
- [itertools](https://docs.rs/itertools/latest/itertools/)
- [uuid](https://docs.rs/uuid/latest/uuid/)

## Sources
- Idea is coming from [@pascal-gujer](https://github.com/pascal-gujer) who raised an [issue](https://github.com/Aorimn/dislocker/issues/294) on the [dislocker](https://github.com/Aorimn/dislocker) project.
- [Implementing BitLocker Drive Encryption for forensic analysis](https://pdf4pro.com/cdn/implementing-bitlocker-drive-encryption-for-19a515.pdf) by Jesse D. Kornblum 
- [libbde](https://github.com/libyal/libbde/blob/main/documentation/BitLocker%20Drive%20Encryption%20%28BDE%29%20format.asciidoc)
