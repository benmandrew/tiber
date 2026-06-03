use clap::{Parser, Subcommand};
use std::fs;
use std::fs::File;
use std::io::{self, BufReader, Cursor, Read};
use tiber::{blockio, cbc, decrypt, encrypt, key::Key128};

fn die(msg: impl std::fmt::Display) -> ! {
    eprintln!("error: {msg}");
    std::process::exit(1);
}

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
        /// Use Cipher Block Chaining (CBC) mode; requires --iv
        #[arg(long, default_value_t = false)]
        cbc: bool,
        /// Initialisation vector as 32 hex characters (required with --cbc)
        #[arg(long)]
        iv: Option<String>,
    },
    /// Decrypt input
    Decrypt {
        /// Path to key file (16 bytes)
        #[arg(short, long)]
        key: String,
        /// Use Cipher Block Chaining (CBC) mode; requires --iv
        #[arg(long, default_value_t = false)]
        cbc: bool,
        /// Initialisation vector as 32 hex characters (required with --cbc)
        #[arg(long)]
        iv: Option<String>,
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
        Commands::Encrypt { key, cbc, iv } => {
            encrypt_command(blocks, cli.output_hex, key, *cbc, iv.as_deref())
        }
        Commands::Decrypt { key, cbc, iv } => {
            decrypt_command(blocks, cli.output_hex, key, *cbc, iv.as_deref())
        }
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

fn encrypt_command(
    blocks: blockio::BlockIter,
    output_hex: bool,
    key_path: &str,
    use_cbc: bool,
    iv_hex: Option<&str>,
) {
    let key = load_key(key_path);
    if use_cbc {
        let iv = parse_iv(iv_hex);
        let mut block_vec: Vec<[u8; 16]> = blocks.collect();
        cbc::encrypt_blocks(&mut block_vec, &key, &iv);
        blockio::write_blocks(&block_vec, output_hex);
    } else {
        blockio::process_blocks(blocks, output_hex, |b| encrypt::encrypt(b, &key));
    }
}

fn decrypt_command(
    blocks: blockio::BlockIter,
    output_hex: bool,
    key_path: &str,
    use_cbc: bool,
    iv_hex: Option<&str>,
) {
    let key = load_key(key_path);
    if use_cbc {
        let iv = parse_iv(iv_hex);
        let mut block_vec: Vec<[u8; 16]> = blocks.collect();
        cbc::decrypt_blocks(&mut block_vec, &key, &iv);
        blockio::write_blocks(&block_vec, output_hex);
    } else {
        blockio::process_blocks(blocks, output_hex, |b| decrypt::decrypt(b, &key));
    }
}

fn parse_iv(iv_hex: Option<&str>) -> [u8; 16] {
    let hex = iv_hex.unwrap_or_else(|| die("--iv is required when using --cbc"));
    let bytes = decode_hex(hex).unwrap_or_else(|e| die(format!("invalid IV: {e}")));
    if bytes.len() != 16 {
        die(format!(
            "IV must be 16 bytes (32 hex characters), got {}",
            bytes.len()
        ));
    }
    bytes.try_into().unwrap()
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
    let bytes =
        fs::read(path).unwrap_or_else(|e| die(format!("failed to read key file '{path}': {e}")));
    if bytes.len() != 16 {
        die(format!(
            "key file must be exactly 16 bytes, got {}",
            bytes.len()
        ));
    }
    Key128::new(bytes.try_into().unwrap())
}

/// Returns a reader over raw input bytes.
/// For hex input, all hex is decoded upfront since it requires full-string parsing.
/// For file/stdin, a buffered reader is returned so blocks are read on demand.
fn make_reader(input: Option<String>, file: Option<String>, input_hex: bool) -> Box<dyn Read> {
    if input_hex {
        let s = read_str(input, file);
        let bytes =
            decode_hex(&s).unwrap_or_else(|e| die(format!("failed to decode hex input: {e}")));
        Box::new(Cursor::new(bytes))
    } else if let Some(path) = file {
        Box::new(BufReader::new(File::open(&path).unwrap_or_else(|e| {
            die(format!("failed to open input file '{path}': {e}"))
        })))
    } else if let Some(s) = input {
        Box::new(Cursor::new(s.into_bytes()))
    } else {
        Box::new(BufReader::new(io::stdin()))
    }
}

fn read_str(input: Option<String>, file: Option<String>) -> String {
    if let Some(path) = file {
        let raw = fs::read(&path)
            .unwrap_or_else(|e| die(format!("failed to read input file '{path}': {e}")));
        String::from_utf8(raw)
            .unwrap_or_else(|_| die(format!("input file '{path}' is not valid UTF-8")))
            .trim()
            .to_string()
    } else if let Some(s) = input {
        s
    } else {
        let mut buf = String::new();
        io::stdin()
            .read_to_string(&mut buf)
            .unwrap_or_else(|e| die(format!("failed to read stdin: {e}")));
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Read;

    #[test]
    fn decode_hex_empty_string_returns_empty_vec() {
        assert_eq!(decode_hex(""), Ok(vec![]));
    }

    #[test]
    fn decode_hex_whitespace_only_returns_empty_vec() {
        assert_eq!(decode_hex("   "), Ok(vec![]));
    }

    #[test]
    fn decode_hex_lowercase_decodes_correctly() {
        assert_eq!(decode_hex("48656c6c6f"), Ok(b"Hello".to_vec()));
    }

    #[test]
    fn decode_hex_uppercase_decodes_correctly() {
        assert_eq!(decode_hex("48656C6C6F"), Ok(b"Hello".to_vec()));
    }

    #[test]
    fn decode_hex_trims_surrounding_whitespace() {
        assert_eq!(decode_hex("  4865  "), Ok(b"He".to_vec()));
    }

    #[test]
    fn decode_hex_all_zeros() {
        assert_eq!(decode_hex("00000000"), Ok(vec![0, 0, 0, 0]));
    }

    #[test]
    fn decode_hex_all_ff() {
        assert_eq!(decode_hex("ffffffff"), Ok(vec![0xff, 0xff, 0xff, 0xff]));
    }

    #[test]
    fn decode_hex_odd_length_returns_error() {
        assert_eq!(
            decode_hex("abc"),
            Err("Hex input must have even length".to_string())
        );
    }

    #[test]
    fn decode_hex_invalid_digit_returns_error() {
        assert!(decode_hex("zz").is_err());
    }

    #[test]
    fn read_str_returns_provided_input() {
        assert_eq!(
            read_str(Some("hello world".to_string()), None),
            "hello world"
        );
    }

    #[test]
    fn read_str_reads_and_trims_file() {
        let path = std::env::temp_dir().join("tiber_test_read_str.txt");
        std::fs::write(&path, "  file content  ").unwrap();
        let result = read_str(None, Some(path.to_str().unwrap().to_string()));
        std::fs::remove_file(&path).unwrap();
        assert_eq!(result, "file content");
    }

    #[test]
    fn make_reader_with_string_input() {
        let mut r = make_reader(Some("hello".to_string()), None, false);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"hello");
    }

    #[test]
    fn make_reader_with_hex_input_decodes_bytes() {
        let mut r = make_reader(Some("4865".to_string()), None, true);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        assert_eq!(buf, b"He");
    }

    #[test]
    fn make_reader_with_file_path() {
        let path = std::env::temp_dir().join("tiber_test_make_reader.bin");
        std::fs::write(&path, b"test data").unwrap();
        let mut r = make_reader(None, Some(path.to_str().unwrap().to_string()), false);
        let mut buf = Vec::new();
        r.read_to_end(&mut buf).unwrap();
        std::fs::remove_file(&path).unwrap();
        assert_eq!(buf, b"test data");
    }

    #[test]
    fn load_key_reads_16_byte_key() {
        let path = std::env::temp_dir().join("tiber_test_load_key.bin");
        let key_bytes = [
            0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf,
            0x4f, 0x3c,
        ];
        std::fs::write(&path, key_bytes).unwrap();
        let key = load_key(path.to_str().unwrap());
        std::fs::remove_file(&path).unwrap();
        assert_eq!(key.key, key_bytes);
    }

    fn write_key(name: &str) -> std::path::PathBuf {
        let path = std::env::temp_dir().join(name);
        std::fs::write(&path, [0u8; 16]).unwrap();
        path
    }

    #[test]
    fn parse_iv_valid_hex() {
        let iv = parse_iv(Some("000102030405060708090a0b0c0d0e0f"));
        assert_eq!(
            iv,
            [
                0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d,
                0x0e, 0x0f
            ]
        );
    }

    #[test]
    fn encrypt_command_cbc_does_not_panic() {
        let key_path = write_key("tiber_test_enc_cbc.bin");
        let reader: Box<dyn Read> = Box::new(std::io::Cursor::new(b"Hello, world!   ".to_vec()));
        encrypt_command(
            blockio::BlockIter::new(reader),
            true,
            key_path.to_str().unwrap(),
            true,
            Some("00000000000000000000000000000000"),
        );
        std::fs::remove_file(&key_path).unwrap();
    }

    #[test]
    fn decrypt_command_cbc_does_not_panic() {
        let key_path = write_key("tiber_test_dec_cbc.bin");
        // NIST SP 800-38A ciphertext block (key=0x00*16, IV=0x00*16)
        let ciphertext = [
            0x66, 0xe9, 0x4b, 0xd4, 0xef, 0x8a, 0x2c, 0x3b, 0x88, 0x4c, 0xfa, 0x59, 0xca, 0x34,
            0x2b, 0x2e,
        ];
        let reader: Box<dyn Read> = Box::new(std::io::Cursor::new(ciphertext.to_vec()));
        decrypt_command(
            blockio::BlockIter::new(reader),
            true,
            key_path.to_str().unwrap(),
            true,
            Some("00000000000000000000000000000000"),
        );
        std::fs::remove_file(&key_path).unwrap();
    }
}
