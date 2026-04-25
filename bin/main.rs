use clap::{Parser, Subcommand};
use std::fs;
use std::io::{self, Read};
use tiber::{decrypt, encrypt, key::Key128};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Input (ASCII or hex). If not provided, reads from stdin.
    #[arg(short, long, conflicts_with = "file")]
    input: Option<String>,
    /// Path to file containing input data. Mutually exclusive with --input.
    #[arg(long, conflicts_with = "input")]
    file: Option<String>,
    /// Interpret input as hex
    #[arg(long, default_value_t = false)]
    input_hex: bool,
    /// Output as hex
    #[arg(long, default_value_t = false)]
    output_hex: bool,
    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand)]
enum Commands {
    /// Encrypt input
    Encrypt {
        /// Path to key file (16 bytes)
        #[arg(short, long)]
        key: String,
    },
    /// Decrypt input
    Decrypt {
        /// Path to key file (16 bytes)
        #[arg(short, long)]
        key: String,
    },
    /// Apply sub_bytes only
    SubBytes {
        /// Apply inverse sub_bytes (for decryption)
        #[arg(short, long, default_value_t = false)]
        inverse: bool,
    },
    /// Apply shift_rows only
    ShiftRows {
        /// Apply inverse shift_rows (for decryption)
        #[arg(short, long, default_value_t = false)]
        inverse: bool,
    },
    /// Apply mix_columns only
    MixColumns {
        /// Apply inverse mix_columns (for decryption)
        #[arg(short, long, default_value_t = false)]
        inverse: bool,
    },
    /// Apply add_round_key for a given round
    AddRoundKey {
        /// Path to key file (16 bytes)
        #[arg(short, long)]
        key: String,
        /// Apply inverse add_round_key (for decryption)
        #[arg(short, long, default_value_t = false)]
        inverse: bool,
        /// Round number
        #[arg(short, long)]
        round: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let mut blocks = get_input_blocks(cli.input.clone(), cli.file.clone(), cli.input_hex);
    match &cli.command {
        Commands::Encrypt { key } => {
            for block in &mut blocks {
                encrypt_command(key, block);
            }
        }
        Commands::Decrypt { key } => {
            for block in &mut blocks {
                decrypt_command(key, block);
            }
        }
        Commands::SubBytes { inverse } => {
            for block in &mut blocks {
                sub_bytes_command(*inverse, block);
            }
        }
        Commands::ShiftRows { inverse } => {
            for block in &mut blocks {
                shift_rows_command(*inverse, block);
            }
        }
        Commands::MixColumns { inverse } => {
            for block in &mut blocks {
                mix_columns_command(*inverse, block);
            }
        }
        Commands::AddRoundKey {
            key,
            inverse,
            round,
        } => {
            for block in &mut blocks {
                add_round_key_command(key, *inverse, *round, block);
            }
        }
    }
    print_blocks(&blocks, cli.output_hex);
}

fn encrypt_command(key_path: &str, state: &mut [u8; 16]) {
    let key_bytes = fs::read(key_path).expect("Failed to read key file");
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes");
    let key = Key128::new(key_bytes.try_into().unwrap());
    encrypt::encrypt(state, &key);
}

fn decrypt_command(key_path: &str, state: &mut [u8; 16]) {
    let key_bytes = fs::read(key_path).expect("Failed to read key file");
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes");
    let key = Key128::new(key_bytes.try_into().unwrap());
    decrypt::decrypt(state, &key);
}

fn sub_bytes_command(inverse: bool, state: &mut [u8; 16]) {
    if inverse {
        decrypt::inv_sub_bytes(state);
    } else {
        encrypt::sub_bytes(state);
    }
}

fn shift_rows_command(inverse: bool, state: &mut [u8; 16]) {
    if inverse {
        decrypt::inv_shift_rows(state);
    } else {
        encrypt::shift_rows(state);
    }
}

fn mix_columns_command(inverse: bool, state: &mut [u8; 16]) {
    if inverse {
        decrypt::inv_mix_columns(state);
    } else {
        encrypt::mix_columns(state);
    }
}

fn add_round_key_command(key_path: &str, inverse: bool, round: usize, state: &mut [u8; 16]) {
    let key_bytes = fs::read(key_path).expect("Failed to read key file");
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes");
    let key = Key128::new(key_bytes.try_into().unwrap());
    let round_key = key.get_round_key(round);
    if inverse {
        decrypt::inv_add_round_key(state, &round_key);
    } else {
        encrypt::add_round_key(state, &round_key);
    }
}

fn get_input_blocks(input: Option<String>, file: Option<String>, input_hex: bool) -> Vec<[u8; 16]> {
    let input_str = read_input_str(input, file);
    let bytes: Vec<u8> = if input_hex {
        decode_hex(&input_str).expect("Failed to decode hex input")
    } else {
        input_str.into_bytes()
    };
    to_blocks(bytes)
}

fn read_input_str(input: Option<String>, file: Option<String>) -> String {
    if let Some(path) = file {
        let raw = fs::read(&path).expect("Failed to read input file");
        String::from_utf8(raw)
            .expect("Input file is not valid UTF-8")
            .trim()
            .to_string()
    } else {
        match input {
            Some(s) => s,
            None => {
                let mut buffer = String::new();
                io::stdin()
                    .read_to_string(&mut buffer)
                    .expect("Failed to read stdin");
                buffer.trim().to_string()
            }
        }
    }
}

fn to_blocks(bytes: Vec<u8>) -> Vec<[u8; 16]> {
    if bytes.is_empty() {
        return vec![[b' '; 16]];
    }
    bytes
        .chunks(16)
        .map(|chunk| {
            let mut block = [b' '; 16];
            block[..chunk.len()].copy_from_slice(chunk);
            block
        })
        .collect()
}

fn print_blocks(blocks: &[[u8; 16]], as_hex: bool) {
    if as_hex {
        for block in blocks {
            print_as_hex(block);
        }
    } else {
        for block in blocks {
            for &b in block {
                print!("{}", b as char);
            }
        }
        println!();
    }
}

fn print_as_hex(bytes: &[u8; 16]) {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(32);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    println!("{}", s);
}

fn decode_hex(s: &str) -> Result<Vec<u8>, String> {
    let s = s.trim();
    if !s.len().is_multiple_of(2) {
        return Err("Hex input must have even length".to_string());
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let chars: Vec<_> = s.chars().collect();
    for i in (0..s.len()).step_by(2) {
        let hi = chars[i].to_digit(16).ok_or("Invalid hex digit")?;
        let lo = chars[i + 1].to_digit(16).ok_or("Invalid hex digit")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
