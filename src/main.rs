#![feature(str_from_utf16_endian)]
#![feature(slice_as_array)]
#[allow(unused)]
use aes::Aes256;
use ccm::{
    Ccm,
    aead::{Aead, KeyInit, OsRng, generic_array::GenericArray},
    consts::{U12, U16, U32},
};
use clap::Parser;
use crc::{CRC_32_ISO_HDLC, Crc};
use gpt::{GptConfig, disk::LogicalBlockSize};
use itertools::Itertools;
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;
use std::process::exit;
use std::time::{SystemTime, UNIX_EPOCH};
use std::{convert::TryInto, vec};
use std::{fmt::Write as Fmt_Write, num::ParseIntError};
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
    Vmk,
    Fvek,
    Validation,
    StartupKey,
    Description,
    FVEKBackup,
    VolumeHeaderBlock,
}

fn get_entry_type(entry_type: u16) -> EntryType {
    match entry_type {
        0x0000 => EntryType::None,
        0x0002 => EntryType::Vmk,
        0x0003 => EntryType::Fvek,
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
    Vmk,
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
        0x0008 => DatumType::Vmk,
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
    Tpm,
    StartupKey,
    TPMAndPin,
    RecoveryPassword,
    Password,
    NotDocumented,
}

fn get_protector_type(protector_type: u16) -> ProtectorType {
    match protector_type {
        0x0000 => ProtectorType::ClearKey,
        0x0100 => ProtectorType::Tpm,
        0x0200 => ProtectorType::StartupKey,
        0x0500 => ProtectorType::TPMAndPin,
        0x0800 => ProtectorType::RecoveryPassword,
        0x2000 => ProtectorType::Password,
        _ => ProtectorType::NotDocumented,
    }
}

const BEK_HEADER_TEMPLATE: [u8; 48] = [
    // BEK file's size (calculated at the end of the generation of the file content)
    0xff, 0x00, 0x00, 0x00, // Version (always 0x0001)
    0x01, 0x00, 0x00, 0x00, // Header's size (always 48)
    0x30, 0x00, 0x00, 0x00, // Copy of BEK file's size
    0xff, 0x00, 0x00, 0x00, // Key protector's GUID (will be retrieved)
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Nonce counter
    0x01, 0x00, 0x00, 0x00, // Encryption type (0x0000 because it is an external key)
    0x00, 0x00, 0x00, 0x00,
    // Creation time (will be modified to reflect the time at which the file is created)
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const BEK_CONTENT_TEMPLATE: [u8; 108] = [
    // Content Size (This entry and its sub-entries)
    0xff, 0x00, // Entry Type (Startup Key)
    0x06, 0x00, // Datum Type (External Key)
    0x09, 0x00, // Version (always 0x0001)
    0x01, 0x00, // External Key GUID
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // External Key modification time
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Entry Size
    0x20, 0x00, // Entry Type
    0x00, 0x00, // Datum Type (String)
    0x02, 0x00, // Version (always 0x0001)
    0x01, 0x00, // String content ("External Key\x00")
    0x45, 0x00, 0x78, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x6c, 0x00,
    0x4b, 0x00, 0x65, 0x00, 0x79, 0x00, 0x00, 0x00, // Entry Size
    0x2c, 0x00, // Entry Type
    0x00, 0x00, // Datum Type (Key)
    0x01, 0x00, // Version (always 0x0001)
    0x01, 0x00, // Key protector type (External Key)
    0x02, 0x20, 0x00, 0x00, // External Key
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const EXTERNAL_KEY_ENTRY_TEMPLATE: [u8; 240] = [
    // Content Size (This entry and its sub-entries)
    0xf0, 0x00, // Entry type
    0x02, 0x00, // Datum type
    0x08, 0x00, // Version (always 0x01)
    0x01, 0x00, // GUID
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Timestamp
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Protector type
    0x00, 0x00, 0x00, 0x02, // String size
    0x20, 0x00, // Entry type
    0x00, 0x00, // Datum type
    0x02, 0x00, // Version (always 0x01)
    0x01, 0x00, // String content ("External Key\x00")
    0x45, 0x00, 0x78, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x6e, 0x00, 0x61, 0x00, 0x6c, 0x00,
    0x4b, 0x00, 0x65, 0x00, 0x79, 0x00, 0x00, 0x00,
    // Entry key protectors (size following)
    0x5c, 0x00, // Entry type
    0x00, 0x00, // Datum type
    0x04, 0x00, // Version (always 0x01)
    0x01, 0x00, // Key protector type (External Key)
    0x02, 0x20, 0x00, 0x00,
    // Entry key protector containing encrypted external key (size following)
    0x50, 0x00, // Entry type
    0x00, 0x00, // Datum type
    0x05, 0x00, // Version (always 0x01)
    0x01, 0x00, // FILETIME
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Nonce counter
    0xff, 0x00, 0x00, 0x00, // MAC
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Payload
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Entry key protector containing encrypted VMK
    0x50, 0x00, // Entry type
    0x00, 0x00, // Datum type
    0x05, 0x00, // Version (always 0x01)
    0x01, 0x00, // FILETIME
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, // Nonce counter
    0xff, 0x00, 0x00, 0x00, // MAC
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    // Payload
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
    0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
];

const CUSTOM_EXTERNAL_KEY_GUID: Uuid = Uuid::from_bytes_le([
    0x50, 0x6f, 0x6f, 0x6b, 0x79, 0x27, 0x20, 0x77, 0x61, 0x73, 0x20, 0x68, 0x65, 0x72, 0x65, 0x21,
]);

const VALIDATION_ENTRY_HEADER: [u8; 8] = [0x50, 0x00, 0x00, 0x00, 0x05, 0x00, 0x01, 0x00];

const EXTERNAL_KEY_HEADER_TEMPLATE: [u8; 12] = [
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x02, 0x20, 0x00, 0x00,
];

const VMK_HEADER_TEMPLATE: [u8; 12] = [
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x03, 0x20, 0x00, 0x00,
];

const VALIDATION_HASH_HEADER_TEMPLATE: [u8; 12] = [
    0x2c, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x05, 0x20, 0x00, 0x00,
];

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "Key Protectors retrieval tool using a VMK and metadata from a disk."
)]
struct Cli {
    /// VMK, key used to decrypt key protectors
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

    /// Disk from which Key Protectors are retrieved
    #[arg(short, long, value_name = "DISKPATH")]
    disk: Option<String>,

    /// Create BEK (BitLocker External Key) file if the Key Protector is configured on the provided disk
    #[arg(short, long)]
    bek: bool,

    /// Add BEK (BitLocker External Key) to the provided disk
    #[arg(short, long)]
    addbek: bool,
}

// AES-256-CCM init
pub type Aes256Ccm = Ccm<Aes256, U16, U12>;

// Utils
//fn filetime_to_unix(filetime_bytes: [u8; 8]) -> u64 {
// Difference in seconds between 1601-01-01 and 1970-01-01 (thank you windows)
//const EPOCH_DIFF: u64 = 11_644_473_600;
//const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

// Convert bytes into 64-bit value (little-endian)
//let filetime_val = u64::from_le_bytes(filetime_bytes);

// Convert from 100ns intervals to seconds
//let total_secs = filetime_val / HUNDRED_NS_PER_SEC;

// Subtract Windows→Unix epoch difference
//total_secs - EPOCH_DIFF
//}

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

fn set_bek_header_vars(guid: Uuid, mut bek_headers: [u8; 48]) -> [u8; 48] {
    // Processing GUID
    let mut guid_raw: [u8; 16] = [0u8; 16];
    guid_raw.copy_from_slice(&bek_headers[16..32]);
    bek_headers[16..32].copy_from_slice(&guid.to_bytes_le());
    //println!("[i] Settting GUID : \n\tFrom :\t{} | {:0>2x?}\n\tTo :\t{} | {:0>2x?}",Uuid::from_bytes_le(guid_raw),guid_raw,guid,guid.to_bytes_le());

    // Processing FILETIME
    let mut filetime_raw: [u8; 8] = [0u8; 8];
    filetime_raw.copy_from_slice(&bek_headers[40..48]);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    bek_headers[40..48].copy_from_slice(&unix_to_filetime(now));
    //println!("[i] Settting FILETIME : \n\tFrom :\t{:?} | {:0>2x?}\n\tTo :\t{:?} | {:0>2x?}",filetime_to_unix(filetime_raw),filetime_raw,now,unix_to_filetime(now));
    bek_headers
}

fn find_fve_metadata_block(disk: String) -> [u64; 3] {
    // Finds the offset at which the first FVE metadata block is located
    let mut offsets: [u64; 3] = [0u64; 3];
    let disk_path = Path::new(&disk);
    let gpt_disk = GptConfig::new().writable(false).open(disk_path).unwrap();
    let partitions = gpt_disk.partitions();

    if partitions.is_empty() {
        eprintln!("[!] No partitions found.");
        exit(1);
    }
    println!(
        "[i] Reading GUID Partition Table.\n[i] Found {} GPT partitions.",
        partitions.len()
    );

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
            let mut offset_metadata_block_1: [u8; 8] = [0; 8];
            let mut offset_metadata_block_2: [u8; 8] = [0; 8];
            let mut offset_metadata_block_3: [u8; 8] = [0; 8];
            let mut bitlocker_identifier_raw: [u8; 16] = [0; 16];
            offset_metadata_block_1.copy_from_slice(&vbr[176..184]);
            offset_metadata_block_2.copy_from_slice(&vbr[184..192]);
            offset_metadata_block_3.copy_from_slice(&vbr[192..200]);
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
            offsets = [
                start_byte_offset + u64::from_le_bytes(offset_metadata_block_1),
                start_byte_offset + u64::from_le_bytes(offset_metadata_block_2),
                start_byte_offset + u64::from_le_bytes(offset_metadata_block_3),
            ];
        }
    }
    offsets
}

fn get_metadata_entries_offset(file: &mut File, offset: u64) -> (u64, Vec<u8>) {
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
    let size_header_block = metadata_addr - offset;
    let mut buffer = vec![0u8; usize::from(size_header_block as u16)];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut buffer).unwrap();
    //println!("{:0>2x?}", buffer);
    (metadata_addr, buffer)
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

    (nonce, mac, payload)
}

fn parse_key_protector_startup_key(guid: Uuid, metadata_entry: Vec<u8>, vmk: String) {
    let mut bek_headers = [0u8; 48];
    let mut bek_content = [0u8; 108];

    bek_headers.copy_from_slice(&BEK_HEADER_TEMPLATE[0..48]);
    bek_content.copy_from_slice(&BEK_CONTENT_TEMPLATE[0..108]);

    bek_headers = set_bek_header_vars(guid, bek_headers.clone());

    // Retrieve MAC, nonce and encrypted startup key from FVE Metadata Entry
    let mut nonce_raw = [0u8; 12];
    let mut mac_raw = [0u8; 16];
    let mut payload_raw = [0u8; 44];
    let mut offset: usize = 0x00;
    let mut size_sub_entry = [0u8; 2];
    loop {
        size_sub_entry.copy_from_slice(&metadata_entry[0x24 + offset..0x24 + offset + 0x02]);
        let mut sub_entry = vec![0u8; usize::from(u16::from_le_bytes(size_sub_entry))];
        sub_entry.copy_from_slice(
            &metadata_entry
                [0x24 + offset..0x24 + offset + usize::from(u16::from_le_bytes(size_sub_entry))],
        );
        if sub_entry[0x04..0x06] == [0x04, 0x00] {
            //println!("[i] Found the sub-entry containing the startup key.");
            //println!("[i] Sub-entry :\t{:0>2x?}", sub_entry);
            nonce_raw.copy_from_slice(&sub_entry[0x14..0x14 + 12]);
            mac_raw.copy_from_slice(&sub_entry[0x20..0x20 + 16]);
            payload_raw.copy_from_slice(&sub_entry[0x30..0x30 + 44]);
            //println!("[i] Nonce :\t{:0>2x?}", nonce_raw);
            //println!("[i] MAC :\t{:0>2x?}", mac_raw);
            //println!("[i] Payload :\t{:0>2x?}", payload_raw);
            break;
        } else {
            offset += usize::from(u16::from_le_bytes(size_sub_entry));
        }
    }

    // Decrypt External Key
    let vmk_raw = decode_hex(&vmk).unwrap();
    let cipher = Aes256Ccm::new_from_slice(&vmk_raw).unwrap();
    let nonce_bytes: &GenericArray<_, U12> = GenericArray::from_slice(&nonce_raw);
    let payload_mac = &[payload_raw.to_vec(), mac_raw.to_vec()].concat();
    let decrypted = cipher.decrypt(nonce_bytes, payload_mac.as_ref());

    //println!("[i] VMK :\t\t{}",vmk);

    let mut plaintext = match decrypted.clone() {
        Ok(text) => encode_hex(&text),
        Err(error) => {
            eprintln!(
                "[!] {error:?} :\tThere was a problem decrypting the payload. This may be due to invalid information."
            );
            exit(1);
        }
    };
    //println!("[i] Unparsed plaintext :\t{:0>2x?}",plaintext);
    plaintext = plaintext[24..plaintext.len()].to_string();
    println!("[i] Startup Key :\t{}", plaintext);

    let bek_content_size = (bek_content.len() as u16).to_le_bytes();
    bek_content[0..2].copy_from_slice(&bek_content_size);
    bek_content[8..24].copy_from_slice(&guid.to_bytes_le());
    bek_content[24..32].copy_from_slice(&nonce_raw[0..8]);
    bek_content[76..108].copy_from_slice(&decrypted.clone().unwrap()[12..decrypted.unwrap().len()]);

    let bek_headers_size = ((bek_content.len() as u32) + (bek_headers.len() as u32)).to_le_bytes();
    bek_headers[0..4].copy_from_slice(&bek_headers_size);
    bek_headers[12..16].copy_from_slice(&bek_headers_size);
    // Printing BEK header
    // println!("[i] BEK header : \n\tFrom :\t{:0>2x?}\n\tTo :\t{:0>2x?}",initial_bek_headers,bek_headers);
    // Printing BEK content
    //println!("[i] BEK content : \n\tFrom :\t{:0>2x?}\n\tTo :\t{:0>2x?}",initial_bek_content,bek_content);

    let bek_file = [bek_headers.to_vec(), bek_content.to_vec()].concat();
    // println!("[i] BEK file :\n{:0>2x?}", bek_file);
    let filename = guid.to_string() + ".bek";
    let new_file = File::create(filename.clone());
    match new_file {
        Ok(mut file) => {
            if file.write_all(&bek_file).is_ok() {
                println!("[r] Wrote the External Key File at ./{filename}.")
            } else {
                eprintln!("[!] Error encountered while writing the External Key at ./{filename}")
            };
        }
        Err(error) => eprintln!("[i] Error while creating the BEK file : {}", error),
    }
}

fn parse_metadata_entries(
    file: &mut File,
    offsets: [u64; 3],
    fve_metadata_block_header_size: usize,
    vmk: String,
    cli: &Cli,
    next_nonce_counter: u32,
    fve_metadata_block_header: Vec<u8>,
) -> (String, String, String) {
    let mut _nonce = String::from("");
    let mut _mac = String::from("");
    let mut _payload = String::from("");
    let mut get_size = [0u8; 0x2];
    let key_vmk = Aes256Ccm::generate_key(&mut OsRng);

    for (counter, offset) in offsets.iter().enumerate() {
        let mut cursor = *offset + fve_metadata_block_header_size as u64;
        let mut metadata_entries: Vec<u8> = Vec::new();

        println!(
            "\n[i] Reading FVE Metadata entries in the block n°{}.\n[i] The offset of the metadata entries is at 0x{:x}.",
            counter + 1,
            offset + fve_metadata_block_header_size as u64
        );

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
                //println!("{:0>2x?}\n", metadata_entry);
                metadata_entries.append(&mut metadata_entry.clone());

                let mut entry_type_raw: [u8; 2] = [0; 2];
                let mut datum_raw: [u8; 2] = [0; 2];

                entry_type_raw.copy_from_slice(&metadata_entry[0x02..0x04]);
                datum_raw.copy_from_slice(&metadata_entry[0x04..0x06]);

                let entry_type = get_entry_type(u16::from_le_bytes(entry_type_raw));
                let datum_type = get_datum_type(u16::from_le_bytes(datum_raw));

                //println!("[i] Entry type :\t\t{entry_type:?}\n[i] Datum type :\t\t{datum_type:?}");
                if entry_type == EntryType::Vmk && datum_type == DatumType::Vmk && counter == 2 {
                    println!("[i] Found an entry containing a Key Protector. Continuing...");
                    let mut key_protector_type_raw: [u8; 2] = [0; 2];
                    key_protector_type_raw.copy_from_slice(&metadata_entry[0x22..0x24]);
                    let mut key_protector_guid_raw: [u8; 16] = [0; 16];
                    key_protector_guid_raw.copy_from_slice(&metadata_entry[0x8..0x18]);
                    let guid = Uuid::from_bytes_le(key_protector_guid_raw);
                    let key_protector_type =
                        get_protector_type(u16::from_le_bytes(key_protector_type_raw));

                    match key_protector_type {
                        ProtectorType::RecoveryPassword => {
                            (_nonce, _mac, _payload) =
                                parse_key_protector_recovery_password(guid, metadata_entry)
                        }
                        ProtectorType::StartupKey => {
                            println!(
                                "[i] A Startup Key appears to be configured.\n[i] The Startup Key has the following GUID :\t\t{{{}}}",
                                guid.to_string().to_uppercase()
                            );
                            if cli.bek {
                                parse_key_protector_startup_key(guid, metadata_entry, vmk.clone())
                            } else {
                                println!(
                                    "[!] The Startup Key was not extracted. To extract it use -b/--bek."
                                )
                            }
                        }
                        _ => println!(
                            "[i] This entry contains a VMK protected using a {:?} Key Protector.\n[i] The Key Protector has the following GUID :\t\t{{{}}}",
                            key_protector_type,
                            guid.to_string().to_uppercase()
                        ),
                    }
                } else if entry_type == EntryType::VolumeHeaderBlock
                    && datum_type == DatumType::OffsetAndSize
                    && cli.addbek
                {
                    file.seek(SeekFrom::Start(
                        cursor + u64::from(u16::from_le_bytes(size_raw)),
                    ))
                    .unwrap();
                    file.read_exact(&mut get_size).unwrap();
                    put_external_key(
                        file,
                        *offset,
                        fve_metadata_block_header_size,
                        cursor - (*offset + fve_metadata_block_header_size as u64),
                        ((cursor + u64::from(u16::from_le_bytes(size_raw)))
                            - (*offset + fve_metadata_block_header_size as u64))
                            + (u16::from_le_bytes(get_size) as u64),
                        vmk.clone(),
                        next_nonce_counter,
                        key_vmk,
                        fve_metadata_block_header.clone(),
                    );
                };
                cursor += u64::from(u16::from_le_bytes(size_raw));
            } else {
                eprintln!(
                    "[!] The size of the retrieved entry appears to be incoherent ({size} bytes), stopping."
                );
                let mut metadata_entry = vec![0u8; 100];
                file.seek(SeekFrom::Start(cursor)).unwrap();
                file.read_exact(&mut metadata_entry).unwrap();
                metadata_entries.append(&mut metadata_entry);
                //println!("{:0>2x?}", metadata_entries);
                break;
                //exit(1);
            }
        }
    }
    (_nonce, _mac, _payload)
}

fn put_external_key(
    file: &mut File,
    offset: u64,
    fve_metadata_block_header_size: usize,
    cursor: u64,
    entries_size: u64,
    vmk: String,
    next_nonce_counter: u32,
    key_vmk: GenericArray<u8, U32>,
    fve_metadata_block_header: Vec<u8>,
) {
    eprintln!(
        "[i] This feature is not implemented yet, it will do nothing beside printing nonsense."
    );

    let mut external_key_entry = [0u8; 240];
    external_key_entry.copy_from_slice(&EXTERNAL_KEY_ENTRY_TEMPLATE[0..240]);

    let now = unix_to_filetime(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs(),
    );

    let key_external_key = decode_hex(&vmk).unwrap();
    let cipher_external_key = Aes256Ccm::new_from_slice(&key_external_key).unwrap();
    let nonce_bytes_external_key =
        [now, (next_nonce_counter as u64).to_le_bytes()].concat()[0..12].to_vec();

    let cipher_vmk = Aes256Ccm::new(&key_vmk);
    let nonce_bytes_vmk =
        [now, ((next_nonce_counter as u64) + 1).to_le_bytes()].concat()[0..12].to_vec();

    println!(
        "[i] Key used to encrypt the External Key :\t{:0>2x?}",
        key_external_key
    );
    println!("[i] Key used to encrypt the VMK :\t\t{:0>2x?}", key_vmk);

    println!("[i] Nonce for external key :\t{nonce_bytes_external_key:0>2x?}");
    println!("[i] Nonce for VMK:\t\t{nonce_bytes_vmk:0>2x?}");

    let nonce_and_counter_external_key: &GenericArray<_, U12> =
        GenericArray::from_slice(&nonce_bytes_external_key);
    let nonce_and_counter_vmk: &GenericArray<_, U12> = GenericArray::from_slice(&nonce_bytes_vmk);

    let payload_ek = [EXTERNAL_KEY_HEADER_TEMPLATE.to_vec(), key_vmk.to_vec()].concat();
    let payload_vmk = [VMK_HEADER_TEMPLATE.to_vec(), key_external_key.to_vec()].concat();

    let ciphertext_external_key =
        cipher_external_key.encrypt(nonce_and_counter_external_key, payload_ek.as_ref());
    let ciphertext_vmk = cipher_vmk.encrypt(nonce_and_counter_vmk, payload_vmk.as_ref());

    let encrypted_external_key = ciphertext_external_key.clone().unwrap()
        [0..ciphertext_external_key.clone().unwrap().len() - 16]
        .to_vec();
    let encrypted_vmk =
        ciphertext_vmk.clone().unwrap()[0..ciphertext_vmk.clone().unwrap().len() - 16].to_vec();

    println!("[i] Payload for external key :\t{encrypted_external_key:0>2x?}");
    println!("[i] Payload for VMK:\t\t{encrypted_vmk:0>2x?}");

    let mac_external_key = ciphertext_external_key.clone().unwrap()[ciphertext_external_key
        .clone()
        .unwrap()
        .len()
        - 16
        ..ciphertext_external_key.unwrap().len()]
        .to_vec();
    let mac_vmk = ciphertext_vmk.clone().unwrap()
        [ciphertext_vmk.clone().unwrap().len() - 16..ciphertext_vmk.unwrap().len()]
        .to_vec();

    println!("[i] MAC for external key :\t{mac_external_key:0>2x?}");
    println!("[i] MAC for VMK:\t\t{mac_vmk:0>2x?}");

    // Entry crafting
    // GUID
    external_key_entry[0x8..0x18].copy_from_slice(&CUSTOM_EXTERNAL_KEY_GUID.to_bytes_le());
    // FILETIMES
    external_key_entry[0x18..0x20].copy_from_slice(&now);
    external_key_entry[0x58..0x60].copy_from_slice(&now);
    external_key_entry[0xa8..0xb0].copy_from_slice(&now);
    // Nonce counters
    external_key_entry[0x60..0x64].copy_from_slice(&(next_nonce_counter as u32).to_le_bytes());
    external_key_entry[0xb0..0xb4]
        .copy_from_slice(&((next_nonce_counter as u32) + 1).to_le_bytes());
    // MACs
    external_key_entry[0x64..0x74].copy_from_slice(&mac_external_key);
    external_key_entry[0xb4..0xc4].copy_from_slice(&mac_vmk);
    // Payloads
    external_key_entry[0x74..0xa0].copy_from_slice(&encrypted_external_key);
    external_key_entry[0xc4..0xf0].copy_from_slice(&encrypted_vmk);
    //println!("{EXTERNAL_KEY_ENTRY_TEMPLATE:0>2x?}");
    //println!("{external_key_entry:0>2x?}");

    // Creating BEK file
    parse_key_protector_startup_key(CUSTOM_EXTERNAL_KEY_GUID, external_key_entry.to_vec(), vmk);

    // Adding entry to the other entries
    let mut initial_entries = vec![0u8; entries_size as usize];
    file.seek(SeekFrom::Start(
        offset + fve_metadata_block_header_size as u64,
    ))
    .unwrap();
    file.read_exact(&mut initial_entries).unwrap();
    //eprintln!("{initial_entries:0>2x?}");
    //println!("{:0>2x?}", initial_entries[0..(cursor as usize)].to_vec());
    let mut size_fve_header_block = [0u8; 2];
    file.seek(SeekFrom::Start(
        offset + fve_metadata_block_header_size as u64 + cursor,
    ))
    .unwrap();
    file.read_exact(&mut size_fve_header_block).unwrap();
    let new_entries = [
        initial_entries[0..(cursor as usize)].to_vec(),
        external_key_entry.to_vec(),
        initial_entries[(cursor as usize)
            ..(cursor as usize) + (u16::from_le_bytes(size_fve_header_block) as usize)]
            .to_vec(),
    ]
    .concat();
    // Validation entry calculation :
    // The hash is calculated using data from the address retrieved by find_fve_metadata_block to the VolumeHeaderBLock entry included. It uses SHA256.
    let mut information_block = [fve_metadata_block_header.clone(), new_entries.clone()].concat();

    // Next nonce counter update (it must be done before computing the hash, or it will break your disk...)
    //println!("{:0>2x?}",information_block.to_vec()[96..100].to_vec());
    information_block[96..100].copy_from_slice(&(next_nonce_counter + 3u32).to_le_bytes());
    // FVE metadata block header size update
    let new_validation_entry_offset = ((information_block.len()>>4) as u16).to_le_bytes();
    information_block[8..10].copy_from_slice(&new_validation_entry_offset);
    // FVE metadata header size update
    let new_entries_size = (information_block.clone()[64..information_block.len()].len() as u32).to_le_bytes();
    information_block[64..68].copy_from_slice(&new_entries_size);
    information_block[76..80].copy_from_slice(&new_entries_size);


    //let test_information_block = [
    //    fve_metadata_block_header.clone(),
    //    initial_entries
    //      [0..(cursor as usize) + (u16::from_le_bytes(size_fve_header_block) as usize)]
    //      .to_vec(),
    //]
    //.concat();
    //println!("{:0>2x?}", information_block);
    //eprintln!("{:0>2x?}", test_information_block);
    let validation_hash: [u8; 32] = *Sha256::digest(information_block.clone())
        .as_array()
        .unwrap();
    //let _test_validation_hash: [u8; 32] = *Sha256::digest(test_information_block.clone())
    //    .as_array()
    //    .unwrap();
    //println!("{:0>2x?}",validation_hash);
    //eprintln!("{:0>2x?}",test_validation_hash);

    let nonce_bytes_validation_hash =
        [now, ((next_nonce_counter as u64) + 2).to_le_bytes()].concat()[0..12].to_vec();
    let nonce_and_counter_validation_hash: &GenericArray<_, U12> =
        GenericArray::from_slice(&nonce_bytes_validation_hash);
    let payload_validation_hash = [
        VALIDATION_HASH_HEADER_TEMPLATE.to_vec(),
        validation_hash.to_vec(),
    ]
    .concat();
    let cipher_validation_hash = Aes256Ccm::new_from_slice(&key_external_key).unwrap();
    let ciphertext_validation_hash_and_mac = cipher_validation_hash
        .encrypt(
            nonce_and_counter_validation_hash,
            payload_validation_hash.as_ref(),
        )
        .unwrap();
    let ciphertext_validation_hash = ciphertext_validation_hash_and_mac
        [0..ciphertext_validation_hash_and_mac.clone().len() - 16]
        .to_vec();
    let mac_validation_hash =
        ciphertext_validation_hash_and_mac[ciphertext_validation_hash_and_mac.clone().len() - 16
            ..ciphertext_validation_hash_and_mac.clone().len()]
            .to_vec();
    //eprintln!("{:0>4x?}",initial_entries[test_information_block.len()-fve_metadata_block_header.len()..initial_entries.len()].to_vec().len());
    //println!("{:0>4x?}",initial_entries[information_block.len()-fve_metadata_block_header.len()..initial_entries.len()].to_vec().len());
    // The folowing is the crc32 checksum of the validation information (https://github.com/Aorimn/dislocker/blob/4ff070f0ea9e56948ab316fb76b91f54dd6727aa/include/dislocker/metadata/metadata.priv.h#L192)
    //eprintln!("{:0>2x?}",initial_entries[test_information_block.len()-fve_metadata_block_header.len()+4..test_information_block.len()-fve_metadata_block_header.len()+8].to_vec());
    // Calculating Information block's crc32
    const CRC32: Crc<u32> = Crc::<u32>::new(&CRC_32_ISO_HDLC);
    let crc32_information_block = CRC32.checksum(&information_block);
    //println!("{:0>2x?}",crc32_information_block.to_le_bytes());
    // Putting it all together
    let validation_entry_size = initial_entries
        [information_block.len() - fve_metadata_block_header.len()..initial_entries.len()]
        .to_vec()
        .len() as u16;
    let mut validation_entry: Vec<u8> = Vec::new();
    validation_entry.append(&mut validation_entry_size.to_le_bytes().to_vec());
    validation_entry.push(0x02);
    validation_entry.push(0x00);
    validation_entry.append(&mut crc32_information_block.to_le_bytes().to_vec());
    validation_entry.append(&mut VALIDATION_ENTRY_HEADER.to_vec());
    validation_entry.append(&mut nonce_and_counter_validation_hash.to_vec());
    validation_entry.append(&mut mac_validation_hash.to_vec());
    validation_entry.append(&mut ciphertext_validation_hash.to_vec());
    // Append 0s
    let padding = vec![0u8; validation_entry_size as usize - validation_entry.len()];
    validation_entry.append(&mut padding.to_vec());
    //println!("{:0>4x}",validation_entry.len());
    //println!("{:0>2x?}",validation_entry);
    //println!("{:0>2x?}",information_block.to_vec()[96..100].to_vec());
    // Debug (again)
    //println!("{:0>2x?}", new_entries);
    //println!("{:0>2x?}", size_fve_header_block);
    // Write metadata block to disk
    let fve_metadata_block = [information_block, validation_entry].concat();
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.write_all(&fve_metadata_block).unwrap();
}

fn main() {
    let cli = Cli::parse();
    let disk = cli.disk.clone();
    let vmk = cli.vmk.clone();
    let (mut nonce, mut mac, mut payload) = ("".to_string(), "".to_string(), "".to_string());
    let mut recovery_pass = Vec::new();

    match disk {
        Some(disk) => {
            // Retrieves offsets where the first FVE metadata block is located
            //let mut file = File::open(disk.clone()).unwrap();
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(disk.clone())
                .unwrap();
            let offsets_metdata_blocks: [u64; 3] = find_fve_metadata_block(disk);

            let mut offsets_metdata_entries = [0u64; 3];
            let mut _fve_metadata_block_header = Vec::new();
            for (counter, offset) in offsets_metdata_blocks.iter().enumerate() {
                println!(
                    "\n[i] Analysing Metadata Block {} at 0x{:x}.",
                    counter + 1,
                    offset
                );

                // Parses metadata headers
                file.seek(SeekFrom::Start(offset + 10)).unwrap();
                let mut version = [0u8; 2];
                let _ = file.read_exact(&mut version).is_ok();
                file.seek(SeekFrom::Start(offset + 80)).unwrap();
                let mut volume_guid_raw = [0u8; 16];
                let _ = file.read_exact(&mut volume_guid_raw).is_ok();
                let volume_guid = Uuid::from_bytes_le(volume_guid_raw);
                println!(
                    "[i] Volume identifier :\t\t{{{}}}",
                    volume_guid.to_string().to_uppercase()
                );
                let mut next_nonce_counter_raw = [0u8; 4];
                let _ = file.read_exact(&mut next_nonce_counter_raw).is_ok();
                let next_nonce_counter = u32::from_le_bytes(next_nonce_counter_raw);
                println!("[i] Next nonce counter : \t{next_nonce_counter}");
                if u16::from_le_bytes(version) == 1 || u16::from_le_bytes(version) == 2 {
                    (offsets_metdata_entries[counter], _fve_metadata_block_header) =
                        get_metadata_entries_offset(&mut file, *offset);
                    if counter == 2 {
                        (nonce, mac, payload) = parse_metadata_entries(
                            &mut file,
                            offsets_metdata_blocks,
                            _fve_metadata_block_header.len(),
                            vmk.clone(),
                            &cli,
                            next_nonce_counter,
                            _fve_metadata_block_header,
                        );
                        recovery_pass = decrypt_recovery_password(
                            vmk.clone(),
                            nonce.clone(),
                            mac.clone(),
                            payload.clone(),
                        );
                    }
                }
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
            recovery_pass =
                decrypt_recovery_password(vmk.clone(), nonce.clone(), mac.clone(), payload.clone());
        }
    }

    println!(
        "\n[i] Information to retrieve the Recovery Password : \n\n[i] VMK :\t{vmk}\n[i] Nonce :\t{nonce}\n[i] MAC :\t{mac}\n[i] Payload :\t{payload}\n"
    );

    println!(
        "[r] Recovery Password :\t{:0>6?}",
        recovery_pass.iter().format("-")
    );
}
