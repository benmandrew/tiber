//! Benchmark AES-128-CBC throughput, mirroring `openssl speed -evp aes-128-cbc`.
use clap::Parser;
use std::hint::black_box;
use std::io::{self, Write};
use std::time::{Duration, Instant};
use tiber::{cbc, key::Key128};

const BLOCK_SIZES: &[usize] = &[16, 64, 256, 1024, 8192, 16384];

#[derive(Parser)]
#[command(name = "tiber-bench", about = "Benchmark AES-128-CBC throughput")]
struct Cli {
    /// Seconds to run each block size
    #[arg(short, long, default_value_t = 3)]
    seconds: u64,
}

fn main() {
    let cli = Cli::parse();
    let key = Key128::new([0u8; 16]);
    let iv = [0u8; 16];
    let mut throughputs: Vec<f64> = Vec::with_capacity(BLOCK_SIZES.len());

    for &block_size in BLOCK_SIZES {
        let n_blocks = block_size / 16;
        let mut data: Vec<[u8; 16]> = vec![[0u8; 16]; n_blocks];
        let target = Duration::from_secs(cli.seconds);
        let start = Instant::now();
        let mut ops: u64 = 0;

        while start.elapsed() < target {
            cbc::encrypt_blocks(black_box(&mut data), &key, &iv);
            ops += 1;
        }

        let elapsed = start.elapsed().as_secs_f64();
        throughputs.push(ops as f64 * block_size as f64 / elapsed / 1000.0);

        println!(
            "Doing AES-128-CBC ops for {}s on {} size blocks: {} AES-128-CBC ops in {:.2}s",
            cli.seconds, block_size, ops, elapsed
        );
        io::stdout().flush().unwrap();
    }

    println!("The 'numbers' are in 1000s of bytes per second processed.");
    println!(
        "{:<16}{:>13}{:>13}{:>13}{:>13}{:>13}{:>13}",
        "type", "16 bytes", "64 bytes", "256 bytes", "1024 bytes", "8192 bytes", "16384 bytes"
    );
    print!("{:<16}", "AES-128-CBC");
    for kbs in &throughputs {
        print!("{:>12.2}k", kbs);
    }
    println!();
}
