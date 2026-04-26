use clap::{Parser, Subcommand};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use tiber::{blockio, decrypt, encrypt, key::Key128};

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
    let reader = make_reader(cli.input.clone(), cli.file.clone(), cli.input_hex);
    let blocks = blockio::BlockIter::new(reader);
    match &cli.command {
        Commands::Encrypt { key } => encrypt_command(blocks, cli.output_hex, key),
        Commands::Decrypt { key } => decrypt_command(blocks, cli.output_hex, key),
        Commands::SubBytes { inverse } => subbytes_command(blocks, cli.output_hex, *inverse),
        Commands::ShiftRows { inverse } => shiftrows_command(blocks, cli.output_hex, *inverse),
        Commands::MixColumns { inverse } => mixcolumns_command(blocks, cli.output_hex, *inverse),
        Commands::AddRoundKey {
            key,
            inverse,
            round,
        } => addroundkey_command(blocks, cli.output_hex, key, *inverse, *round),
    }
}

fn encrypt_command(blocks: blockio::BlockIter, output_hex: bool, key_path: &str) {
    let key = load_key(key_path);
    blockio::process_blocks(blocks, output_hex, |b| encrypt::encrypt(b, &key));
}

fn decrypt_command(blocks: blockio::BlockIter, output_hex: bool, key_path: &str) {
    let key = load_key(key_path);
    blockio::process_blocks(blocks, output_hex, |b| decrypt::decrypt(b, &key));
}

fn subbytes_command(blocks: blockio::BlockIter, output_hex: bool, inverse: bool) {
    blockio::process_blocks(blocks, output_hex, move |b| {
        if inverse {
            decrypt::inv_sub_bytes(b)
        } else {
            encrypt::sub_bytes(b)
        }
    });
}

fn shiftrows_command(blocks: blockio::BlockIter, output_hex: bool, inverse: bool) {
    blockio::process_blocks(blocks, output_hex, move |b| {
        if inverse {
            decrypt::inv_shift_rows(b)
        } else {
            encrypt::shift_rows(b)
        }
    });
}

fn mixcolumns_command(blocks: blockio::BlockIter, output_hex: bool, inverse: bool) {
    blockio::process_blocks(blocks, output_hex, move |b| {
        if inverse {
            decrypt::inv_mix_columns(b)
        } else {
            encrypt::mix_columns(b)
        }
    });
}

fn addroundkey_command(
    blocks: blockio::BlockIter,
    output_hex: bool,
    key_path: &str,
    inverse: bool,
    round: usize,
) {
    let key = load_key(key_path);
    let round_key = key.get_round_key(round);
    blockio::process_blocks(blocks, output_hex, move |b| {
        if inverse {
            decrypt::inv_add_round_key(b, &round_key)
        } else {
            encrypt::add_round_key(b, &round_key)
        }
    });
}

fn load_key(path: &str) -> Key128 {
    let bytes = fs::read(path).expect("Failed to read key file");
    assert_eq!(bytes.len(), 16, "Key must be 16 bytes");
    Key128::new(bytes.try_into().unwrap())
}

/// Returns a reader over raw input bytes.
/// For hex input, all hex is decoded upfront since it requires full-string parsing.
/// For file/stdin, a buffered reader is returned so blocks are read on demand.
fn make_reader(input: Option<String>, file: Option<String>, input_hex: bool) -> Box<dyn Read> {
    if input_hex {
        let s = read_str(input, file);
        let bytes = decode_hex(&s).expect("Failed to decode hex input");
        Box::new(Cursor::new(bytes))
    } else if let Some(path) = file {
        Box::new(BufReader::new(
            File::open(path).expect("Failed to open input file"),
        ))
    } else if let Some(s) = input {
        Box::new(Cursor::new(s.into_bytes()))
    } else {
        Box::new(BufReader::new(io::stdin()))
    }
}

fn read_str(input: Option<String>, file: Option<String>) -> String {
    if let Some(path) = file {
        let raw = fs::read(&path).expect("Failed to read input file");
        String::from_utf8(raw)
            .expect("Input file is not valid UTF-8")
            .trim()
            .to_string()
    } else if let Some(s) = input {
        s
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .expect("Failed to read stdin");
        buf.trim().to_string()
    }
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
