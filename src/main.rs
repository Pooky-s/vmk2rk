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
use std::io::{Read, Seek, SeekFrom, Write, stdin, stdout};
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
// Difference in seconds between 1601-01-01 and 1970-01-01 (thank you windows)
const EPOCH_DIFF: u64 = 11_644_473_600;
const HUNDRED_NS_PER_SEC: u64 = 10_000_000;

#[derive(Debug)]
struct FILETIME { 
    array: [u8; 8],
    timestamp: u64,
}

impl FILETIME {
    fn from_unix(unix_time: u64) -> Self {
        let filetime_intervals: u64 = (unix_time + EPOCH_DIFF) * HUNDRED_NS_PER_SEC;
        let array = filetime_intervals.to_le_bytes();
        let timestamp = unix_time;

        FILETIME {
            array,
            timestamp,
        }
    }

    fn from_filetime(filetime_bytes: [u8; 8]) -> Self {
        let filetime_val = u64::from_le_bytes(filetime_bytes);
        let total_secs = filetime_val / HUNDRED_NS_PER_SEC;
        let array = filetime_bytes;
        let timestamp = total_secs - EPOCH_DIFF;
        
        FILETIME {
            array,
            timestamp,
        }
    }
}

#[derive(Debug)]
enum FVEData {
    // TODO : Implement structs instead
    VolumeMasterKeyEntry(Uuid,FILETIME,ProtectorType,Vec<Box<FVE_Metadata_Entry>>),
    AesCcmEncryptedKey([u8;8],[u8;4],[u8;16],Vec<u8>),
    StretchKey(EncryptionMethod, [u8;16], Box<FVE_Metadata_Entry>),
    Description(String),
    Raw(Vec<u8>),
}

#[derive(Debug)]
struct FVE_Metadata_Entry {
    entry_size: u16,
    entry_type: EntryType,
    datum_type: DatumType,
    version: u16,
    data: FVEData,
}

impl FVE_Metadata_Entry {
    fn read(entry: Vec<u8>) -> Self {
        let entry_size = u16::from_le_bytes(*entry[0..2].as_array().unwrap());
        let entry_type = get_entry_type(u16::from_le_bytes(*entry[2..4].as_array().unwrap()));
        let datum_type = get_datum_type(u16::from_le_bytes(*entry[4..6].as_array().unwrap()));
        let version = u16::from_le_bytes(*entry[6..8].as_array().unwrap());

        let data = match entry_type {
            EntryType::Vmk => {
                if datum_type == DatumType::Vmk {
                    let protector_guid = Uuid::from_bytes_le(*entry[8..24].as_array().unwrap());
                    let filetime = FILETIME::from_filetime(*entry[24..32].as_array().unwrap());
                    let protector_type = get_protector_type(u16::from_le_bytes(*entry[34..36].as_array().unwrap()));
                    let mut sub_entries_raw = entry[36..].to_vec();
                    let mut sub_entries = Vec::new();
                    while sub_entries_raw.len() > 0 {
                        let size = u16::from_le_bytes(*sub_entries_raw[0..2].as_array().unwrap());
                        let sub_entry = FVE_Metadata_Entry::read(sub_entries_raw[0..size as usize].to_vec());
                        sub_entries.push(Box::new(sub_entry));
                        sub_entries_raw = sub_entries_raw[size as usize..].to_vec();
                    }

                    FVEData::VolumeMasterKeyEntry(protector_guid, filetime, protector_type,sub_entries)
                } else {
                    FVEData::Raw(entry[8..].to_vec())
                }
            },
            EntryType::None => {
                if datum_type == DatumType::AESCCMEncryptedKey {
                    let nonce_date= *entry[8..16].as_array().unwrap();
                    let nonce_counter = *entry[16..20].as_array().unwrap();
                    let mac = *entry[20..36].as_array().unwrap();
                    let payload = entry[36..].to_vec();

                    FVEData::AesCcmEncryptedKey(nonce_date,nonce_counter,mac,payload)
                } else if datum_type == DatumType::StretchKey {
                    let encryption_method = get_encryption_method(u32::from_le_bytes(*entry[8..12].as_array().unwrap()));
                    let salt = *entry[12..28].as_array().unwrap();
                    let sub_entry = FVE_Metadata_Entry::read(entry[28..].to_vec());
                    FVEData::StretchKey(encryption_method, salt, Box::new(sub_entry))
                } else {
                    FVEData::Raw(entry[8..].to_vec())
                }
            },
            EntryType::NotDocumented => {
                if datum_type == DatumType::AESCCMEncryptedKey {
                    let nonce_date= *entry[8..16].as_array().unwrap();
                    let nonce_counter = *entry[16..20].as_array().unwrap();
                    let mac = *entry[20..36].as_array().unwrap();
                    let payload = entry[36..].to_vec();

                    FVEData::AesCcmEncryptedKey(nonce_date,nonce_counter,mac,payload)
                } else {
                    FVEData::Raw(entry[8..].to_vec())
                }
            },
            EntryType::Description => FVEData::Description(String::from_utf16le(&entry[8..]).unwrap_or_default()),
            _ => FVEData::Raw(entry[8..].to_vec()),
        };

        FVE_Metadata_Entry {
            entry_size,
            entry_type,
            datum_type,
            version,
            data,
        }
    }
}

struct FVE_Metadata_Header {
    size: u32,
    version: u32,
    volume_guid: Uuid,
    next_nonce_counter: u32,
    encryption_method: EncryptionMethod,
    creation_time: FILETIME,
}

impl FVE_Metadata_Header {
    fn read(fve_metadata_header_raw: [u8;48]) -> Self {
        let size = u32::from_le_bytes(*fve_metadata_header_raw[0..4].as_array().unwrap());
        let version = u32::from_le_bytes(*fve_metadata_header_raw[4..8].as_array().unwrap());
        let volume_guid = Uuid::from_bytes_le(*fve_metadata_header_raw[16..32].as_array().unwrap());
        let next_nonce_counter = u32::from_le_bytes(*fve_metadata_header_raw[32..36].as_array().unwrap());
        let encryption_method = get_encryption_method(u32::from_le_bytes(*fve_metadata_header_raw[36..40].as_array().unwrap()));
        let creation_time = FILETIME::from_filetime(*fve_metadata_header_raw[40..48].as_array().unwrap());

        FVE_Metadata_Header {
            size,
            version,
            volume_guid,
            next_nonce_counter,
            encryption_method,
            creation_time
        } 
    }
}

struct FVE_Metadata_Block {
    signature: String,
    validation_block_offset: u16,
    version: u16,
    fve_metadata_header: FVE_Metadata_Header,
    fve_metadata_entries: Vec<FVE_Metadata_Entry>,
}

impl FVE_Metadata_Block {
    fn read(offset: u64, file: &mut File) -> Self {
        // Retrieve block size wihtout the validation part
        let mut validation_block_offset_raw = [0u8;2];

        file.seek(SeekFrom::Start(offset+8)).unwrap();
        file.read_exact(&mut validation_block_offset_raw).unwrap_or_default();

        let validation_block_offset = u16::from_le_bytes(validation_block_offset_raw)<<4;

        let mut fve_metadata_block_raw = vec![0u8; validation_block_offset as usize];

        // Retrieve whole block
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut fve_metadata_block_raw).unwrap_or_default();

        // Set signature and version
        let signature = String::from_utf8(fve_metadata_block_raw[0..8].to_vec()).unwrap_or_default();
        let version = u16::from_le_bytes(*fve_metadata_block_raw[10..12].as_array().unwrap());

        // Initialize FVE Metdata Block Header 
        let fve_metadata_header = FVE_Metadata_Header::read(*fve_metadata_block_raw[64..112].as_array().unwrap());
        
        // Initialize FVE Metdata Entries
        let mut fve_metadata_entries_raw = fve_metadata_block_raw[112..].to_vec();
        let mut fve_metadata_entries: Vec<FVE_Metadata_Entry> = Vec::new();

        //println!("{:0>2x?}",fve_metadata_entries_raw);
        while fve_metadata_entries_raw.len() > 0 {
            let size = u16::from_le_bytes(*fve_metadata_entries_raw[0..2].as_array().unwrap());
            let entry = FVE_Metadata_Entry::read(fve_metadata_entries_raw[0..size as usize].to_vec());
            //println!("[i] {:?} {:?}\n\t{:0>2x?}",entry.entry_type, entry.datum_type, entry.data);
            fve_metadata_entries.push(entry);
            fve_metadata_entries_raw = fve_metadata_entries_raw[size as usize..].to_vec();
        }

        FVE_Metadata_Block { 
            signature,
            validation_block_offset,
            version,
            fve_metadata_header,
            fve_metadata_entries
        }
    }
}

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

#[derive(Debug, PartialEq)]
enum EncryptionMethod {
    NotEncrypted,
    StretchKey,
    AesCcm256,
    AesCbc128Diffuser,
    AesCbc256Diffuser,
    AesCbc128,
    AesCbc256,
    AesXts128,
    AesXts256,
    NotDocumented,
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

fn get_encryption_method(encryption_method: u32) -> EncryptionMethod {
    match encryption_method {
        0x0000 => EncryptionMethod::NotEncrypted,
        0x1000 => EncryptionMethod::StretchKey,
        0x1001 => EncryptionMethod::StretchKey,
        0x2000 => EncryptionMethod::AesCcm256,
        0x2001 => EncryptionMethod::AesCcm256,
        0x2002 => EncryptionMethod::AesCcm256,
        0x2003 => EncryptionMethod::AesCcm256,
        0x2004 => EncryptionMethod::AesCcm256,
        0x2005 => EncryptionMethod::AesCcm256,
        0x8000 => EncryptionMethod::AesCbc128Diffuser,
        0x8001 => EncryptionMethod::AesCbc256Diffuser,
        0x8002 => EncryptionMethod::AesCbc128,
        0x8003 => EncryptionMethod::AesCbc256,
        0x8004 => EncryptionMethod::AesXts128,
        0x8005 => EncryptionMethod::AesXts256,
        _ => EncryptionMethod::NotDocumented,
    }
}

#[derive(Parser)]
#[command(
    version,
    about,
    long_about = "Key Protectors retrieval tool using a VMK and metadata from a disk."
)]
struct Cli {
    /// VMK, key used to decrypt key protectors.
    #[arg(required = true, short, long, value_name = "Key", default_value_t = String::from("7e63180cb55e15fa62ff4a2cac1bec4ca2ae145b8b92b59b8674e1f2169bcc8d"))]
    vmk: String,

    /// Disk from which Key Protectors are retrieved.
    #[arg(short, long, value_name = "DISKPATH")]
    disk: Option<String>,

    /// Create BEK (BitLocker External Key) file if the Key Protector is configured on the provided disk.
    #[arg(short, long)]
    bek: bool,

    /// Add BEK (BitLocker External Key) to the provided disk. WARNING : DO NOT USE UNLESS YOU DON'T CARE ABOUT BREAKING THE TARGET DISK (This means make backups).
    #[arg(short, long)]
    addbek: bool,
}

// AES-256-CCM init
pub type Aes256Ccm = Ccm<Aes256, U16, U12>;

fn find_fve_metadata_blocks(disk: String, file: &mut File) -> [u64; 3] {
    let mut offsets_fve_metdata_blocks = [0u64; 3];
    let mut found_offsets: Vec<[u64; 3]> = Vec::new();
    let gpt_disk = GptConfig::new().writable(false).open(disk).unwrap();
    let partitions = gpt_disk.partitions();
    let mut vbr = [0u8; 512];

    if partitions.is_empty() {
        eprintln!("[!] No partitions found.");
        exit(1);
    } else {
        println!("[i] Found {} GPT partitions.", partitions.len());
    }

    for (index, part) in partitions.values().enumerate() {
        let start_byte_offset = match part.bytes_start(LB_SIZE) {
            Ok(offset) => {
                println!("[i] Got a start offset at 0x{:x}", offset);
                offset
            }
            Err(e) => {
                eprintln!("[!] Failed to get start offset: {}", e);
                continue;
            }
        };

        file.seek(SeekFrom::Start(start_byte_offset)).unwrap();
        file.read_exact(&mut vbr).unwrap_or_default();

        let signature = &vbr[0..11];

        if vec![SEVEN_SIGNATURE, VISTA_SIGNATURE, TOGO_SIGNATURE].contains(&signature) {
            println!(
                "[i] The partition {} appears to be encrypted using BitLocker. Volume headers begins at 0x{start_byte_offset:x}.",
                index + 1
            );

            let bitlocker_identifier = Uuid::from_bytes_le(*vbr[160..176].as_array().unwrap());

            println!(
                "[i] BitLocker identifier :\t{{{}}} ",
                bitlocker_identifier.to_string().to_uppercase()
            );

            found_offsets.push([
                start_byte_offset + u64::from_le_bytes(*vbr[176..184].as_array().unwrap()),
                start_byte_offset + u64::from_le_bytes(*vbr[184..192].as_array().unwrap()),
                start_byte_offset + u64::from_le_bytes(*vbr[192..200].as_array().unwrap()),
            ]);
        }
    }
    match found_offsets.len() {
        0 => {
            eprintln!("[!] No BitLocker encrypted partition found.");
            exit(1);
        }
        1 => offsets_fve_metdata_blocks = found_offsets[0],
        _ => {
            print!(
                "[i] Found {} BitLocker encrypted partitions. Provide the index of the partition you want to analyse (from 1 to {}).\n>:",
                found_offsets.len(),
                found_offsets.len()
            );
            let _ = stdout().flush();
            let mut input: String = String::new();
            let _ = stdin().read_line(&mut input);
            match input.parse::<usize>() {
                Ok(num) => {
                    if num > 0 && num < found_offsets.len() {
                        offsets_fve_metdata_blocks = found_offsets[num - 1]
                    }
                }
                Err(e) => {
                    eprintln!("[!] Invalid input: {}", e);
                    exit(1);
                }
            }
        }
    }
    offsets_fve_metdata_blocks
}

fn parse_fve_metadata_blocks(
    offsets_fve_metdata_blocks: [u64; 3],
    file: &mut File,
) -> Vec<FVE_Metadata_Block> {
    let mut fve_metadata_blocks = Vec::new();
    for offset in offsets_fve_metdata_blocks {
        fve_metadata_blocks.push(FVE_Metadata_Block::read(offset, file));
    }
    fve_metadata_blocks
}

fn main() {
    let cli = Cli::parse();
    let disk = cli.disk.clone();

    match disk {
        Some(disk) => {
            let mut file = OpenOptions::new()
                .read(true)
                .write(true)
                .open(disk.clone())
                .unwrap_or_else(|_| {
                    eprintln!("[!] The path to the disk you provided is invalid.");
                    exit(1);
                });
            let offsets_fve_metdata_blocks: [u64; 3] =
                find_fve_metadata_blocks(disk, &mut file);
            println!("{:x?}", offsets_fve_metdata_blocks);
            let fve_metadata_blocks =
                parse_fve_metadata_blocks(offsets_fve_metdata_blocks, &mut file);
        }
        None => {
            eprintln!("[!] You must provide a path to a disk to analyse.");
            exit(1);
        }
    }
}
