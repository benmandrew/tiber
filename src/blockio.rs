//! Block I/O utilities for reading, processing, and outputting 16-byte blocks in parallel.
//!
//! Provides the `BlockIter` iterator and `process_blocks` function for efficient block-wise operations.
use rayon::prelude::*;
use std::io::{self, BufWriter, Read, Write};

/// Iterator over space-padded 16-byte blocks from a reader.
/// Empty input produces one all-spaces block, matching single-block behaviour.
pub struct BlockIter {
    reader: Box<dyn Read>,
    first: bool,
    exhausted: bool,
}

impl BlockIter {
    /// Create a new BlockIter from a boxed reader.
    pub fn new(reader: Box<dyn Read>) -> Self {
        Self {
            reader,
            first: true,
            exhausted: false,
        }
    }
}

impl Iterator for BlockIter {
    type Item = [u8; 16];

    fn next(&mut self) -> Option<[u8; 16]> {
        if self.exhausted {
            return None;
        }
        let mut block = [b' '; 16];
        let mut total = 0;
        while total < 16 {
            match self.reader.read(&mut block[total..]) {
                Ok(0) => break,
                Ok(n) => total += n,
                Err(e) => panic!("Failed to read input: {}", e),
            }
        }
        if total == 0 {
            self.exhausted = true;
            return if self.first {
                self.first = false;
                Some([b' '; 16])
            } else {
                None
            };
        }
        self.first = false;
        if total < 16 {
            self.exhausted = true;
        }
        Some(block)
    }
}

/// Process all blocks using the provided function, outputting as hex or binary.
/// The function `f` is applied to each block in parallel.
/// If `output_hex` is true, output is hex-encoded, otherwise raw binary.
pub fn process_blocks<F>(blocks: BlockIter, output_hex: bool, f: F)
where
    F: Fn(&mut [u8; 16]) + Sync,
{
    if output_hex {
        process_blocks_hex(blocks, f);
    } else {
        process_blocks_bin(blocks, f);
    }
}

fn process_blocks_hex<F>(blocks: BlockIter, f: F)
where
    F: Fn(&mut [u8; 16]) + Sync,
{
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut block_vec: Vec<[u8; 16]> = blocks.collect();
    let hex_lines: Vec<String> = block_vec
        .par_iter_mut()
        .map(|block| {
            f(block);
            block
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect();
    let hex_output = hex_lines.join("\n") + "\n";
    writer.write_all(hex_output.as_bytes()).unwrap();
    writer.flush().unwrap();
}

fn process_blocks_bin<F>(blocks: BlockIter, f: F)
where
    F: Fn(&mut [u8; 16]) + Sync,
{
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut block_vec: Vec<[u8; 16]> = blocks.collect();
    let processed_blocks: Vec<[u8; 16]> = block_vec
        .par_iter_mut()
        .map(|block| {
            f(block);
            *block
        })
        .collect();
    for block in processed_blocks {
        writer.write_all(&block).unwrap();
    }
    writeln!(writer).unwrap();
    writer.flush().unwrap();
}
