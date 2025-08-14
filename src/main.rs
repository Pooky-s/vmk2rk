#![feature(str_from_utf16_endian)]
#![feature(slice_as_array)]
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

// Declare constants (needed to verify the offset found)
const VISTA_SIGNATURE: &[u8] = b"\xeb\x52\x90-FVE-FS-";
const SEVEN_SIGNATURE: &[u8] = b"\xeb\x58\x90-FVE-FS-";
const TOGO_SIGNATURE: &[u8] = b"\xeb\x58\x90MSWIN4.1";
const LB_SIZE: LogicalBlockSize = LogicalBlockSize::Lb512;

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
}

// AES-256-CCM init
pub type Aes256Ccm = Ccm<Aes256, U16, U12>;

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
    println!("[i] Found {} GPT partitions.", partitions.len());

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
            println!("[i] The partition {index} appears to be encrypted. Volume headers starts at 0x{start_byte_offset:x}");
            let mut offset_metadata_block: [u8; 8] = [0; 8];
            offset_metadata_block.copy_from_slice(&vbr[176..184]);
            println!(
                "[i] Address of the first FVE metadata block is 0x{:x}",
                start_byte_offset + u64::from_le_bytes(offset_metadata_block)
            );
            offset = start_byte_offset + u64::from_le_bytes(offset_metadata_block);
        }
    }
    offset
}

fn get_metadata_entries_offset(file: &mut File, offset: u64) -> u64 {
    // Returns the metadata entries offset
    let mut metadata_addr: Vec<u64> = Vec::new();
    let mut get_size = [0u8; 10];
    file.seek(SeekFrom::Start(offset)).unwrap();
    file.read_exact(&mut get_size).unwrap();
    println!("[i] Metadata header offset : {offset:x}");

    // Retrieves metadata header size
    let mut size_raw: [u8; 2] = [0; 2];
    size_raw.clone_from_slice(&get_size[0x08..0x0a]);
    let size: usize = usize::from(u16::from_le_bytes(size_raw));

    if size > 0 {
        // Retrieves metadata header according to retrieved size
        let mut header = vec![0u8; 0x72];
        file.seek(SeekFrom::Start(offset)).unwrap();
        file.read_exact(&mut header).unwrap();

        // Retrieves volume name and other information
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
            "[i] Volume information : {}",
            String::from_utf16le(&volume_name).unwrap()
        );
        println!("[i] Metadata version : {version}");

        metadata_addr.append(&mut vec![
            offset + 0x78 + u64::from(u16::from_le_bytes(volume_name_size_raw) - 8),
        ]);
    }
    metadata_addr[0]
}

fn parse_metadata_entries(file: &mut File, offset: u64) -> Vec<String> {
    let mut key_protector_data: Vec<String> = Vec::new();
    let mut get_size = [0u8; 0x2];
    println!("[i] Metadata entries offset : {offset:x}");
    let mut blocks_to_read = true;
    let mut cursor = offset.clone();

    while blocks_to_read {
        // Retrieves key protector size
        file.seek(SeekFrom::Start(cursor)).unwrap();
        file.read_exact(&mut get_size).unwrap();

        let mut size_raw: [u8; 2] = [0; 2];
        size_raw.copy_from_slice(&get_size[0x00..0x02]);
        let size: usize = usize::from(u16::from_le_bytes(size_raw));

        // If size is too big, or 0, 
        if size > 0 && size < 1000 {
            // Retrieves metadata header according to retrieved size
            let mut metadata_entry = vec![0u8; size];
            file.seek(SeekFrom::Start(cursor)).unwrap();
            file.read_exact(&mut metadata_entry).unwrap();

            let mut entry_type_raw: [u8; 2] = [0; 2];
            let mut datum_raw: [u8; 2] = [0; 2];

            entry_type_raw.copy_from_slice(&metadata_entry[0x02..0x04]);
            datum_raw.copy_from_slice(&metadata_entry[0x04..0x06]);

            let entry_type = u16::from_le_bytes(entry_type_raw);
            let datum = u16::from_le_bytes(datum_raw);

            if entry_type == 0x02 && datum == 0x08 {
                println!(
                    "[i] Found an entry that might be the nested entry containing the encrypted Recovery Password. Continuing..."
                );
                let mut protection_type_raw: [u8; 2] = [0; 2];
                protection_type_raw.copy_from_slice(
                    &metadata_entry[0x08 + 0x10 + 0x08 + 0x02..0x08 + 0x10 + 0x08 + 0x02 + 0x02],
                );
                let protection_type = u16::from_le_bytes(protection_type_raw);

                if protection_type == 0x0800 {
                    println!(
                        "[i] This entry appears to contain the encrypted Recovery Password. Continuing..."
                    );
                    let mut salt_offset = usize::from(0x08u16 + 0x14u16);

                    let mut key_protector_type_raw: [u8; 2] = [0; 2];
                    let mut key_protector_size = 0u16;
                    let mut key_protector_size_raw: [u8; 2] = [0; 2];

                    key_protector_type_raw.copy_from_slice(
                        &metadata_entry[0x28..0x2a],
                    );
                    while u16::from_le_bytes(key_protector_type_raw) != 0x03 {
                        key_protector_size_raw.copy_from_slice(
                            &metadata_entry[0x24..0x26],
                        );
                        key_protector_size = u16::from_le_bytes(key_protector_size_raw);
                        salt_offset += usize::from(key_protector_size);
                        key_protector_type_raw.copy_from_slice(
                            &metadata_entry[0x28 + usize::from(key_protector_size)..0x2a + usize::from(key_protector_size)],
                        );
                    }

                    key_protector_size_raw.copy_from_slice(
                        &metadata_entry[0x24 + salt_offset..0x26 + salt_offset],
                    );
                    key_protector_size = u16::from_le_bytes(key_protector_size_raw);
                    let mut key_protector = vec![0u8; usize::from(key_protector_size)];
                    key_protector.copy_from_slice(
                        &metadata_entry[0x24 + salt_offset..0x24 + salt_offset + usize::from(key_protector_size)],
                    );

                    let mut nonce: [u8; 12] = [0; 12];
                    let mut mac: [u8; 16] = [0; 16];
                    let mut payload = vec![0u8; usize::from(key_protector_size - 36)];

                    nonce.copy_from_slice(&key_protector[0x08..0x14]);
                    mac.copy_from_slice(&key_protector[0x14..0x24]);
                    payload.copy_from_slice(
                        &key_protector[0x24..0x24 + (usize::from(key_protector_size) - 36)],
                    );

                    println!(
                        "[r] Successfully retrieved information :\n\n[i] Nonce :\t{}\n[i] MAC :\t{}\n[i] Payload :\t{}\n",
                        encode_hex(&nonce),
                        encode_hex(&mac),
                        encode_hex(&payload)
                    );

                    key_protector_data.append(&mut vec![encode_hex(&nonce)]);
                    key_protector_data.append(&mut vec![encode_hex(&mac)]);
                    key_protector_data.append(&mut vec![encode_hex(&payload)]);
                    break;
                } else {
                    println!(
                        "[!] The entry does not contain the encrypted Recovery Password. Continuing..."
                    )
                }
            };

            cursor += u64::from(u16::from_le_bytes(size_raw));
        } else {
            blocks_to_read = false;
            eprintln!("[!] Something went wrong, the size retrieved appears to be incoherent.");
            exit(1);
        }
    }
    key_protector_data
}

fn main() {
    let cli = Cli::parse();
    let disk = cli.disk;
    let vmk = cli.vmk;
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
            if encode_hex(&version) == "0200" || encode_hex(&version) == "0100" {
                let offset = get_metadata_entries_offset(&mut file, offset);
                println!("[i] Provided information : \n\n[i] VMK :\t{vmk}\n");
                let key_protector_data = parse_metadata_entries(&mut file, offset);
                recovery_pass = decrypt_recovery_password(
                    vmk,
                    key_protector_data[0].clone(),
                    key_protector_data[1].clone(),
                    key_protector_data[2].clone(),
                );
            }
        }
        None => {
            println!("[i] No file selected. Continuing...");
            // Variables
            let nonce = cli.nonce;
            let mac = cli.mac;
            let payload = cli.payload;

            println!(
                "[i] Provided information : \n\n[i] VMK :\t{vmk}\n[i] Nonce :\t{nonce}\n[i] MAC :\t{mac}\n[i] Payload :\t{payload}\n"
            );

            // Verifications
            if vmk.len() != 64 || nonce.len() != 24 || mac.len() != 32 || payload.len() != 56 {
                eprintln!(
                    "[!] Error :\tThe length of one of the following information is incorrect :\n\t- the VMK;\n\t- the nonce;\n\t- the MAC;\n\t- the payload.\nVerify the input you provided."
                );
                exit(1)
            }
            recovery_pass = decrypt_recovery_password(vmk, nonce, mac, payload);
        }
    }
    println!(
        "[r] Recovery Password :\t{:0>6?}",
        recovery_pass.iter().format("-")
    );
}
