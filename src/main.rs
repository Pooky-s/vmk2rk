#![feature(str_from_utf16_endian)]
#![feature(slice_as_array)]
#[allow(unused)]
use aes::Aes256;
use ccm::{
    Ccm,
    aead::{Aead, KeyInit, generic_array::GenericArray},
    consts::{U12, U16},
};
use clap::Parser;
use gpt::{GptConfig, disk::LogicalBlockSize};
use itertools::Itertools;
use std::convert::TryInto;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;
use std::process::exit;
use std::{fmt::Write, num::ParseIntError};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

// Declare constants (needed to verify the offset found)
const VISTA_SIGNATURE: &[u8] = b"\xeb\x52\x90-FVE-FS-";
const SEVEN_SIGNATURE: &[u8] = b"\xeb\x58\x90-FVE-FS-";
const TOGO_SIGNATURE: &[u8] = b"\xeb\x58\x90MSWIN4.1";
const LB_SIZE: LogicalBlockSize = LogicalBlockSize::Lb512;

#[derive(Debug, PartialEq)]
enum EntryType {
    None,
    NotDocumented,
    VMK,
    FVEK,
    Validation,
    StartupKey,
    Description,
    FVEKBackup,
    VolumeHeaderBlock,
}

fn get_entry_type(entry_type: u16) -> EntryType {
    match entry_type {
        0x0000 => EntryType::None,
        0x0002 => EntryType::VMK,
        0x0003 => EntryType::FVEK,
        0x0004 => EntryType::Validation,
        0x0006 => EntryType::StartupKey,
        0x0007 => EntryType::Description,
        0x000b => EntryType::FVEKBackup,
        0x000f => EntryType::VolumeHeaderBlock,
        _ => EntryType::NotDocumented,
    }
}

#[derive(Debug, PartialEq)]
enum DatumType {
    Erased,
    Key,
    UnicodeString,
    StretchKey,
    UseKey,
    AESCCMEncryptedKey,
    TPMEncodedKey,
    Validation,
    VMK,
    ExternalKey,
    Update,
    Error,
    NotDocumented,
    OffsetAndSize,
}

fn get_datum_type(datum_type: u16) -> DatumType {
    match datum_type {
        0x0000 => DatumType::Erased,
        0x0001 => DatumType::Key,
        0x0002 => DatumType::UnicodeString,
        0x0003 => DatumType::StretchKey,
        0x0004 => DatumType::UseKey,
        0x0005 => DatumType::AESCCMEncryptedKey,
        0x0006 => DatumType::TPMEncodedKey,
        0x0007 => DatumType::Validation,
        0x0008 => DatumType::VMK,
        0x0009 => DatumType::ExternalKey,
        0x000a => DatumType::Update,
        0x000b => DatumType::Error,
        0x000f => DatumType::OffsetAndSize,
        _ => DatumType::NotDocumented,
    }
}

#[derive(Debug, PartialEq)]
enum ProtectorType {
    ClearKey,
    TPM,
    StartupKey,
    TPMAndPin,
    RecoveryPassword,
    Password,
    NotDocumented,
}

fn get_protector_type(protector_type: u16) -> ProtectorType {
    match protector_type {
        0x0000 => ProtectorType::ClearKey,
        0x0100 => ProtectorType::TPM,
        0x0200 => ProtectorType::StartupKey,
        0x0500 => ProtectorType::TPMAndPin,
        0x0800 => ProtectorType::RecoveryPassword,
        0x2000 => ProtectorType::Password,
        _ => ProtectorType::NotDocumented,
    }
}

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "Recovery Password retrieval tool using a VMK and metadata from a disk."
)]
struct Cli {
    /// VMK, key used to decrypt the Recovery Password
    #[arg(required = true, short, long, value_name = "Key", default_value_t = String::from("7e63180cb55e15fa62ff4a2cac1bec4ca2ae145b8b92b59b8674e1f2169bcc8d"))]
    vmk: String,

    /// Nonce used to decrypt the Recovery Password
    #[arg(short, long, value_name = "Nonce", default_value_t = String::from("a0d6eb7c2b03dc010f000000"))]
    nonce: String,

    /// MAC used to decrypt the Recovery Password
    #[arg(short, long, value_name = "MAC", default_value_t = String::from("709fbe999a0b37582d230a7cdbc40ba0"))]
    mac: String,

    /// Payload containing the encrypted Recovery Password
    #[arg(short, long, value_name = "Payload", default_value_t = String::from("487c4e3f137759409f626bae6e39d24e59d283b6b1e19db6678646ce"))]
    payload: String,

    /// Disk to retrieve the nonce, MAC and encrypted Recovery Password
    #[arg(short, long, value_name = "DISKPATH")]
    disk: Option<String>,

    /// Create BEK (BitLocker External Key) file if the key protector is configured on the provided disk (Not implemented yet)
    #[arg(short, long)]
    bek: bool,
}

// AES-256-CCM init
pub type Aes256Ccm = Ccm<Aes256, U16, U12>;

// Utils
fn filetime_to_unix(filetime_bytes: [u8; 8]) -> u64 {
    // Difference in seconds between 1601-01-01 and 1970-01-01 (thank you windows)
    const EPOCH_DIFF: u64 = 11_644_473_600;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

    // Convert bytes into 64-bit value (little-endian)
    let filetime_val = u64::from_le_bytes(filetime_bytes);

    // Convert from 100ns intervals to seconds
    let total_secs = filetime_val / HUNDRED_NS_PER_SEC;

    // Subtract Windows→Unix epoch difference
    total_secs - EPOCH_DIFF
}

fn unix_to_filetime(unix_time: u64) -> [u8; 8] {
    // Difference in seconds between 1601-01-01 and 1970-01-01 (thank you windows)
    const EPOCH_DIFF: u64 = 11_644_473_600;
    const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

    let filetime_intervals: u64 = (unix_time + EPOCH_DIFF) * HUNDRED_NS_PER_SEC;

    // Convert into little-endian byte array
    filetime_intervals.to_le_bytes()
}

pub fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}

pub fn swap_endianness(vec: &[u8]) -> Vec<u8> {
    vec.chunks_exact(2)
        .flat_map(|chunk| {
            let word = u16::from_be_bytes(chunk.try_into().unwrap());
            word.to_le_bytes()
        })
        .collect()
}

// Internal functions
fn format_recovery_key(vec: &[u8]) -> Vec<u32> {
    // Takes each part of the recovery password and multiply it by 11
    vec.chunks_exact(2)
        .map(|chunk| {
            let value = u32::from(u16::from_be_bytes(chunk.try_into().unwrap()));
            value * 11
        })
        .collect()
}

fn decrypt_recovery_password(vmk: String, nonce: String, mac: String, payload: String) -> Vec<u32> {
    // Takes in input :
    //     - The provided VMK, used as the key
    //     - The Nonce, used to encrypt and decrypt the payload
    //     - The MAC, used to verify there is no collision
    //     - The payload, containing the encrypted recovery password
    // Outputs the nearly usable recovery key
    let vmk_bytes = decode_hex(&vmk).unwrap();
    let cipher = Aes256Ccm::new_from_slice(&vmk_bytes).unwrap();
    let binding = decode_hex(&nonce).unwrap();
    let nonce_bytes: &GenericArray<_, U12> = GenericArray::from_slice(&binding);
    let payload_mac = payload.clone() + &mac;
    let decrypted = cipher.decrypt(nonce_bytes, decode_hex(&payload_mac).unwrap().as_ref());

    let plaintext = match decrypted {
        Ok(text) => encode_hex(&text),
        Err(error) => {
            eprintln!(
                "[!] {error:?} :\tThere was a problem decrypting the payload. This may be due to invalid information."
            );
            exit(1);
        }
    };

    // Transform to usable Recovery Key
    let recovery_pass_hex = &plaintext[24..56];
    let recovery_pass_raw = decode_hex(recovery_pass_hex).unwrap();
    let recovery_pass_raw_swapped = swap_endianness(&recovery_pass_raw);
    let _recovery_pass_hex_swapped = encode_hex(&recovery_pass_raw_swapped);

    format_recovery_key(&recovery_pass_raw_swapped)
}

pub fn format_addresses(vec: &[u8]) -> Vec<u64> {
    vec.chunks_exact(8)
        .map(|chunk| u64::from_le_bytes(chunk.try_into().unwrap()))
        .collect()
}

fn find_fve_metadata_block(disk: String) -> u64 {
    // Finds the offset at which the first FVE metadata block is located
    let mut offset = 0u64;
    let disk_path = Path::new(&disk);
    let gpt_disk = GptConfig::new().writable(false).open(disk_path).unwrap();
    let partitions = gpt_disk.partitions();

    if partitions.is_empty() {
        eprintln!("[!] No partitions found.");
        exit(1);
    }
    println!("[i] Reading GUID Partition Table.\n[i] Found {} GPT partitions.", partitions.len());

    for (index, part) in partitions.values().enumerate() {
        let start_byte_offset = match part.bytes_start(LB_SIZE) {
            Ok(offset) => offset,
            Err(e) => {
                eprintln!("[!]  Failed to get start offset: {}", e);
                continue;
            }
        };
        let mut file = File::open(disk_path).unwrap();
        file.seek(SeekFrom::Start(start_byte_offset)).unwrap();

        let mut vbr = [0u8; 512];
        file.read_exact(&mut vbr).unwrap();

        // Verify Boot Entry Point and Filesystem Signature
        if &vbr[0..11] == SEVEN_SIGNATURE
            || &vbr[0..11] == VISTA_SIGNATURE
            || &vbr[0..11] == TOGO_SIGNATURE
        {
            let mut offset_metadata_block: [u8; 8] = [0; 8];
            let mut bitlocker_identifier_raw: [u8; 16] = [0; 16];
            offset_metadata_block.copy_from_slice(&vbr[176..184]);
            bitlocker_identifier_raw.copy_from_slice(&vbr[160..176]);
            let bitlocker_identifier = Uuid::from_bytes_le(bitlocker_identifier_raw);
            println!(
                "[i] The partition {} appears to be encrypted. Volume headers begins at 0x{start_byte_offset:x}.",
                index + 1
            );
            println!(
                "[i] BitLocker identifier :\t{{{}}} ",
                bitlocker_identifier.to_string().to_uppercase()
            );
            offset = start_byte_offset + u64::from_le_bytes(offset_metadata_block);
        }
    }
    offset
}

fn get_metadata_entries_offset(file: &mut File, offset: u64) -> u64 {
    // Returns the metadata entries offset
    let mut metadata_addr = 0u64;
    let mut get_size = [0u8; 10];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut get_size).unwrap();

    // Retrieves metadata header size
    let mut size_raw: [u8; 2] = [0; 2];
    size_raw.clone_from_slice(&get_size[0x08..0x0a]);
    let size: usize = usize::from(u16::from_le_bytes(size_raw));

    if size > 0 {
        // Retrieves metadata header according to retrieved size
        let mut header = vec![0u8; 0x72];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut header).unwrap();

        // Retrieves volume name, letter and date of encryption (?)
        let mut volume_name_size_raw: [u8; 2] = [0; 2];
        volume_name_size_raw.clone_from_slice(&header[0x70..0x72]);
        let volume_name_size = u16::from_le_bytes(volume_name_size_raw);
        let mut volume_name = vec![0u8; usize::from(volume_name_size) - 8];
        file.seek(SeekFrom::Start(offset + 0x78)).unwrap();
        file.read_exact(&mut volume_name).unwrap();

        // Retrieves version
        let mut version_raw: [u8; 2] = [0; 2];
        version_raw.clone_from_slice(&header[0x0a..0x0c]);
        let version = u16::from_le_bytes(version_raw);

        println!(
            "[i] Volume information :\t{}",
            String::from_utf16le(&volume_name).unwrap()
        );
        println!("[i] Metadata version :\t\t{version}");

        metadata_addr = offset + 0x78 + u64::from(u16::from_le_bytes(volume_name_size_raw) - 8);
    }
    metadata_addr
}

fn parse_key_protector_recovery_password(
    guid: Uuid,
    metadata_entry: Vec<u8>,
) -> (String, String, String) {
    println!(
        "[i] This entry contains the encrypted Recovery Password.\n[i] The Recovery Password has the following GUID :\t{{{}}}",
        guid.to_string().to_uppercase()
    );

    let mut offset = usize::from(0x08u16 + 0x14u16);
    let mut key_protector_type_raw: [u8; 2] = [0; 2];
    let mut _key_protector_size = 0u16;
    let mut key_protector_size_raw: [u8; 2] = [0; 2];

    key_protector_type_raw.copy_from_slice(&metadata_entry[0x28..0x2a]);
    while get_datum_type(u16::from_le_bytes(key_protector_type_raw)) != DatumType::StretchKey {
        key_protector_size_raw.copy_from_slice(&metadata_entry[0x24..0x26]);
        _key_protector_size = u16::from_le_bytes(key_protector_size_raw);
        offset += usize::from(_key_protector_size);
        key_protector_type_raw.copy_from_slice(
            &metadata_entry
                [0x28 + usize::from(_key_protector_size)..0x2a + usize::from(_key_protector_size)],
        );
    }

    key_protector_size_raw.copy_from_slice(&metadata_entry[0x24 + offset..0x26 + offset]);
    _key_protector_size = u16::from_le_bytes(key_protector_size_raw);

    let mut key_protector = vec![0u8; usize::from(_key_protector_size)];
    key_protector.copy_from_slice(
        &metadata_entry[0x24 + offset..0x24 + offset + usize::from(_key_protector_size)],
    );

    let mut nonce_bytes: [u8; 12] = [0; 12];
    let mut mac_bytes: [u8; 16] = [0; 16];
    let mut payload_bytes = vec![0u8; usize::from(_key_protector_size - 36)];

    nonce_bytes.copy_from_slice(&key_protector[0x08..0x14]);
    mac_bytes.copy_from_slice(&key_protector[0x14..0x24]);
    payload_bytes
        .copy_from_slice(&key_protector[0x24..0x24 + (usize::from(_key_protector_size) - 36)]);

    let nonce = encode_hex(&nonce_bytes);
    let mac = encode_hex(&mac_bytes);
    let payload = encode_hex(&payload_bytes);

    return (nonce, mac, payload);
}

fn parse_key_protector_startup_key(
    guid: Uuid,
    _metadata_entry: Vec<u8>,
) {
    println!(
        "[i] A Startup Key appears to be configured. In a future release, the tool should be able to generate a BEK file based on the metadata.\n[i] The Startup Key has the following GUID :\t\t{{{}}}",
        guid.to_string().to_uppercase()
    );
    let initial_bek_headers : [u8; 48] = [
        // BEK file's size (calculated at the end of the generation of the file content)
        0xff,0x00,0x00,0x00,
        // Version (always 0x0001)
        0x01,0x00,0x00,0x00,
        // Header's size (always 48)
        0x30,0x00,0x00,0x00,
        // Copy of BEK file's size 
        0xff,0x00,0x00,0x00,
        // Key protector's GUID (will be retrieved)
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff,
        // Nonce counter
        0x01,0x00,0x00,0x00,
        // Encryption type (0x0000 because it is an external key)
        0x00,0x00,0x00,0x00,
        // Creation time (will be modified to reflect the time at which the file is created)
        0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff
    ];
    let mut bek_headers = [0u8; 48];
    bek_headers.copy_from_slice(&initial_bek_headers[0..48]);

    // Processing GUID
    let mut guid_raw : [u8; 16] = [0u8; 16];
    guid_raw.copy_from_slice(&bek_headers[16..32]);
    bek_headers[16..32].copy_from_slice(&guid.to_bytes_le());
    println!("[i] Settting GUID : \n\tFrom :\t{} | {:0>2x?}\n\tTo :\t{} | {:0>2x?}",Uuid::from_bytes_le(guid_raw),guid_raw,guid,guid.to_bytes_le());

    // Processing FILETIME
    let mut filetime_raw : [u8; 8] = [0u8; 8];
    filetime_raw.copy_from_slice(&bek_headers[40..48]);
    let now = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_secs();
    bek_headers[40..48].copy_from_slice(&unix_to_filetime(now));
    println!("[i] Settting FILETIME : \n\tFrom :\t{:?} | {:0>2x?}\n\tTo :\t{:?} | {:0>2x?}",filetime_to_unix(filetime_raw),filetime_raw,now,unix_to_filetime(now));

    // Printing BEK header
    println!("[i] BEK header : \n\tFrom :\t{:0>2x?}\n\tTo :\t{:0>2x?}",initial_bek_headers,bek_headers);
}

fn parse_metadata_entries(file: &mut File, offset: u64) -> (String, String, String) {
    let mut _nonce = String::from("");
    let mut _mac = String::from("");
    let mut _payload = String::from("");
    let mut get_size = [0u8; 0x2];
    println!("\n[i] Reading FVE Metadata entries.\n[i] The offset of the metadata entries is at 0x{offset:x}.");
    let mut cursor = offset.clone();

    loop {
        // Retrieves key protector size
        file.seek(SeekFrom::Start(cursor)).unwrap();
        file.read_exact(&mut get_size).unwrap();

        let mut size_raw: [u8; 2] = [0; 2];
        size_raw.copy_from_slice(&get_size[0x00..0x02]);
        let size: usize = usize::from(u16::from_le_bytes(size_raw));

        // Pass if size is too big, or 0,
        if size > 0 && size < 1000 {
            // Retrieves metadata header according to retrieved size
            let mut metadata_entry = vec![0u8; size];
            file.seek(SeekFrom::Start(cursor)).unwrap();
            file.read_exact(&mut metadata_entry).unwrap();

            let mut entry_type_raw: [u8; 2] = [0; 2];
            let mut datum_raw: [u8; 2] = [0; 2];

            entry_type_raw.copy_from_slice(&metadata_entry[0x02..0x04]);
            datum_raw.copy_from_slice(&metadata_entry[0x04..0x06]);

            let entry_type = get_entry_type(u16::from_le_bytes(entry_type_raw));
            let datum_type = get_datum_type(u16::from_le_bytes(datum_raw));

            //println!("[i] Entry type :\t\t{entry_type:?}\n[i] Datum type :\t\t{datum_type:?}");
            if entry_type == EntryType::VMK && datum_type == DatumType::VMK {
                println!("[i] Found an entry containing a Key Protector. Continuing...");
                let mut key_protector_type_raw: [u8; 2] = [0; 2];
                key_protector_type_raw.copy_from_slice(&metadata_entry[0x22..0x24]);
                let mut key_protector_guid_raw: [u8; 16] = [0; 16];
                key_protector_guid_raw.copy_from_slice(&metadata_entry[0x8..0x18]);
                let guid = Uuid::from_bytes_le(key_protector_guid_raw);
                let key_protector_type =
                    get_protector_type(u16::from_le_bytes(key_protector_type_raw));
                //println!("{key_protector_type:?}");

                match key_protector_type {
                    ProtectorType::RecoveryPassword => (_nonce, _mac, _payload) = parse_key_protector_recovery_password(guid, metadata_entry),
                    ProtectorType::StartupKey => parse_key_protector_startup_key(guid, metadata_entry),
                    _ => println!(
                        "[i] This entry contains a VMK protected using a {:?} Key Protector.\n[i] The Key Protector has the following GUID :\t\t{{{}}}",
                        key_protector_type,
                        guid.to_string().to_uppercase()
                    ),
                }
            };
            cursor += u64::from(u16::from_le_bytes(size_raw));
        } else {
            eprintln!("[!] The size of the retrieved entry appears to be incoherent, stopping.");
            break;
            //exit(1);
        }
    }
    return (_nonce, _mac, _payload);
}

fn main() {
    let cli = Cli::parse();
    let disk = cli.disk;
    let vmk = cli.vmk;
    let (mut nonce, mut mac, mut payload) = ("".to_string(), "".to_string(), "".to_string());
    let mut recovery_pass = Vec::new();

    match disk {
        Some(disk) => {
            // Retrieves the offset were the first FVE metadata block is located
            let mut file = File::open(disk.clone()).unwrap();
            let mut offset = find_fve_metadata_block(disk);

            // Parses metadata headers
            file.seek(SeekFrom::Start(offset + 10)).unwrap();
            let mut version = [0u8; 2];
            let _ = file.read_exact(&mut version).is_ok();
            file.seek(SeekFrom::Start(offset + 80)).unwrap();
            let mut volume_guid_raw = [0u8; 16];
            let _ = file.read_exact(&mut volume_guid_raw).is_ok();
            let volume_guid = Uuid::from_bytes_le(volume_guid_raw);
            println!(
                "\n[i] Reading FVE Metadata block 1 located at 0x{offset:x}.\n[i] Volume identifier :\t\t{{{}}}",
                volume_guid.to_string().to_uppercase()
            );
            if u16::from_le_bytes(version) == 1 || u16::from_le_bytes(version) == 2 {
                offset = get_metadata_entries_offset(&mut file, offset);
                (nonce, mac, payload) = parse_metadata_entries(&mut file, offset);
                recovery_pass = decrypt_recovery_password(
                    vmk.clone(),
                    nonce.clone(),
                    mac.clone(),
                    payload.clone(),
                );
            }
        }
        None => {
            println!("[i] No file selected. Continuing...");
            // Variables
            (nonce, mac, payload) = (cli.nonce, cli.mac, cli.payload);

            // Verifications
            if vmk.len() != 64 || nonce.len() != 24 || mac.len() != 32 || payload.len() != 56 {
                eprintln!(
                    "[!] Error :\tThe length of one of the following information is incorrect :\n\t- the VMK;\n\t- the nonce;\n\t- the MAC;\n\t- the payload.\nVerify the input you provided."
                );
                exit(1)
            }
            recovery_pass = decrypt_recovery_password(
                    vmk.clone(), 
                    nonce.clone(), 
                    mac.clone(), 
                    payload.clone()
                );
        }
    }

    println!(
        "\n[i] Information to retrieve the Recovery Password : \n\n[i] VMK :\t{vmk}\n[i] Nonce :\t{nonce}\n[i] MAC :\t{mac}\n[i] Payload :\t{payload}\n"
    );

    println!(
        "[r] Recovery Password :\t{:0>6?}",
        recovery_pass.iter().format("-")
    );

    if cli.bek {
        println!("I will soon make BEK files if it is among the key protectors of the given disk.");
    }
}
