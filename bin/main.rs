use clap::{Args, Parser, Subcommand};
use std::fs;
use std::io::{self, Read};
use tiber::{decrypt, encrypt, key::Key128, util};

#[derive(Parser)]
#[command(author, version, about, long_about = None)]
struct Cli {
    /// Path to key file (16 bytes)
    #[arg(short, long)]
    key: String,
    /// Input (16 bytes, ASCII or hex). If not provided, reads from stdin.
    #[arg(short, long)]
    input: Option<String>,
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
    Encrypt(EncryptCmd),
    /// Decrypt input
    Decrypt(DecryptCmd),
}

#[derive(Args)]
struct EncryptCmd {
    #[command(subcommand)]
    subcmd: Option<EncryptSubroutine>,
}

#[derive(Subcommand)]
enum EncryptSubroutine {
    /// Apply sub_bytes only
    SubBytes,
    /// Apply shift_rows only
    ShiftRows,
    /// Apply mix_columns only
    MixColumns,
    /// Apply add_round_key for a given round
    AddRoundKey {
        /// Round number
        round: usize,
    },
}

#[derive(Args)]
struct DecryptCmd {
    #[command(subcommand)]
    subcmd: Option<DecryptSubroutine>,
}

#[derive(Subcommand)]
enum DecryptSubroutine {
    /// Apply inv_sub_bytes only
    SubBytes,
    /// Apply inv_shift_rows only
    ShiftRows,
    /// Apply inv_mix_columns only
    MixColumns,
    /// Apply inv_add_round_key for a given round
    AddRoundKey {
        /// Round number
        round: usize,
    },
}

fn main() {
    let cli = Cli::parse();
    let key_bytes = fs::read(&cli.key).expect("Failed to read key file");
    assert_eq!(key_bytes.len(), 16, "Key must be 16 bytes");
    let key = Key128::new(key_bytes.try_into().unwrap());
    match cli.command {
        Commands::Encrypt(cmd) => {
            encrypt(cmd, &key, cli.input, cli.input_hex, cli.output_hex);
        }
        Commands::Decrypt(cmd) => {
            decrypt(cmd, &key, cli.input, cli.input_hex, cli.output_hex);
        }
    }
}

fn encrypt(
    cmd: EncryptCmd,
    key: &Key128,
    input: Option<String>,
    input_hex: bool,
    output_hex: bool,
) {
    let mut state = get_input_bytes(input, input_hex);
    match cmd.subcmd {
        Some(EncryptSubroutine::SubBytes) => encrypt::sub_bytes(&mut state),
        Some(EncryptSubroutine::ShiftRows) => encrypt::shift_rows(&mut state),
        Some(EncryptSubroutine::MixColumns) => encrypt::mix_columns(&mut state),
        Some(EncryptSubroutine::AddRoundKey { round }) => {
            let round_key = key.get_round_key(round);
            encrypt::add_round_key(&mut state, &round_key);
        }
        None => encrypt::encrypt(&mut state, key),
    }
    if output_hex {
        print_hex(&state);
    } else {
        util::print_as_text(&state);
    }
}

fn decrypt(
    cmd: DecryptCmd,
    key: &Key128,
    input: Option<String>,
    input_hex: bool,
    output_hex: bool,
) {
    let mut state = get_input_bytes(input, input_hex);
    match cmd.subcmd {
        Some(DecryptSubroutine::SubBytes) => decrypt::inv_sub_bytes(&mut state),
        Some(DecryptSubroutine::ShiftRows) => decrypt::inv_shift_rows(&mut state),
        Some(DecryptSubroutine::MixColumns) => decrypt::inv_mix_columns(&mut state),
        Some(DecryptSubroutine::AddRoundKey { round }) => {
            let round_key = key.get_round_key(round);
            decrypt::inv_add_round_key(&mut state, &round_key);
        }
        None => decrypt::decrypt(&mut state, key),
    }
    if output_hex {
        print_hex(&state);
    } else {
        util::print_as_text(&state);
    }
}

fn get_input_bytes(input: Option<String>, input_hex: bool) -> [u8; 16] {
    let input_str = match input {
        Some(s) => s,
        None => {
            let mut buffer = String::new();
            io::stdin()
                .read_to_string(&mut buffer)
                .expect("Failed to read stdin");
            buffer.trim().to_string()
        }
    };
    let bytes = if input_hex {
        let b = decode_hex(&input_str).expect("Failed to decode hex input");
        assert!(b.len() <= 16, "Hex input must be at most 16 bytes");
        b
    } else {
        let b = input_str.as_bytes();
        assert!(b.len() <= 16, "Input must be at most 16 ASCII bytes");
        b.to_vec()
    };
    let mut arr = [b' '; 16];
    arr[..bytes.len()].copy_from_slice(&bytes);
    arr
}

fn print_hex(bytes: &[u8; 16]) {
    println!("{}", encode_hex(bytes));
}

fn encode_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        s.push(HEX[(b >> 4) as usize] as char);
        s.push(HEX[(b & 0xf) as usize] as char);
    }
    s
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
