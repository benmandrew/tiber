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
    F: Fn(&mut [u8; 16]) + Sync + Send,
{
    if output_hex {
        process_blocks_hex(blocks, f);
    } else {
        process_blocks_bin(blocks, f);
    }
}

/// Write pre-processed blocks to stdout as hex or binary.
pub fn write_blocks(blocks: &[[u8; 16]], output_hex: bool) {
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    if output_hex {
        write_hex(&mut writer, blocks);
    } else {
        write_bin(&mut writer, blocks);
    }
    writer.flush().unwrap();
}

fn write_hex<W: Write>(writer: &mut W, blocks: &[[u8; 16]]) {
    let hex_lines: Vec<String> = blocks
        .iter()
        .map(|block| {
            block
                .iter()
                .map(|b| format!("{:02x}", b))
                .collect::<String>()
        })
        .collect();
    writer
        .write_all((hex_lines.join("\n") + "\n").as_bytes())
        .unwrap();
}

fn write_bin<W: Write>(writer: &mut W, blocks: &[[u8; 16]]) {
    for block in blocks {
        writer.write_all(block).unwrap();
    }
    writeln!(writer).unwrap();
}

fn process_blocks_hex<F>(blocks: BlockIter, f: F)
where
    F: Fn(&mut [u8; 16]) + Sync + Send,
{
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut block_vec: Vec<[u8; 16]> = blocks.collect();
    block_vec.par_iter_mut().for_each(f);
    write_hex(&mut writer, &block_vec);
    writer.flush().unwrap();
}

fn process_blocks_bin<F>(blocks: BlockIter, f: F)
where
    F: Fn(&mut [u8; 16]) + Sync + Send,
{
    let stdout = io::stdout();
    let mut writer = BufWriter::new(stdout.lock());
    let mut block_vec: Vec<[u8; 16]> = blocks.collect();
    block_vec.par_iter_mut().for_each(f);
    write_bin(&mut writer, &block_vec);
    writer.flush().unwrap();
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    fn iter_from(data: &[u8]) -> BlockIter {
        BlockIter::new(Box::new(Cursor::new(data.to_vec())))
    }

    #[test]
    fn empty_input_yields_one_space_block() {
        let mut iter = iter_from(b"");
        assert_eq!(iter.next(), Some([b' '; 16]));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn short_input_pads_remainder_with_spaces() {
        let mut iter = iter_from(b"Hi");
        let block = iter.next().unwrap();
        assert_eq!(&block[..2], b"Hi");
        assert_eq!(block[2..], [b' '; 14]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn exact_16_bytes_yields_one_full_block() {
        let data = [1u8; 16];
        let mut iter = iter_from(&data);
        assert_eq!(iter.next(), Some(data));
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn two_full_blocks_yields_two_blocks() {
        let data: Vec<u8> = (0u8..32).collect();
        let mut iter = iter_from(&data);
        assert_eq!(
            iter.next().unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        assert_eq!(
            iter.next().unwrap(),
            [
                16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn partial_second_block_is_padded_with_spaces() {
        let data: Vec<u8> = (0u8..20).collect();
        let mut iter = iter_from(&data);
        assert_eq!(
            iter.next().unwrap(),
            [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15]
        );
        let b2 = iter.next().unwrap();
        assert_eq!(&b2[..4], &[16u8, 17, 18, 19]);
        assert_eq!(b2[4..], [b' '; 12]);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn exhausted_iterator_keeps_returning_none() {
        let mut iter = iter_from(b"Hello, world!");
        while iter.next().is_some() {}
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn write_hex_encodes_blocks_as_newline_separated_hex() {
        let blocks = [[0x00u8; 16], [0xffu8; 16]];
        let mut buf = Vec::new();
        write_hex(&mut buf, &blocks);
        assert_eq!(
            String::from_utf8(buf).unwrap(),
            "00000000000000000000000000000000\nffffffffffffffffffffffffffffffff\n"
        );
    }

    #[test]
    fn write_bin_writes_raw_bytes_followed_by_newline() {
        let blocks = [[0xabu8; 16]];
        let mut buf = Vec::new();
        write_bin(&mut buf, &blocks);
        let mut expected = vec![0xabu8; 16];
        expected.push(b'\n');
        assert_eq!(buf, expected);
    }
}
