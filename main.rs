#[inline]
pub fn u64_usize(n: u64) -> usize {
    n.try_into().expect("FATAL: u64 length to usize error")
}

#[inline]
pub fn usize_u64(n: usize) -> u64 {
    n.try_into().expect("FATAL: usize length to u64 error")
}

use cshake::{CShake, CShakeCustom, cshake_customs, Absorb, Squeeze, SqueezeXor};

cshake_customs! {
    CIPHER_CUSTOM -> "__shakenc__file-stream-cipher"
    HASH_CUSTOM -> "__shakenc__file-hash"
    RAND_CUSTOM -> "__shakenc__random-generator"
}

struct Context {
    cipher: CShake<CIPHER_CUSTOM>,
    ihash: Option<CShake<HASH_CUSTOM>>,
    ohash: Option<CShake<HASH_CUSTOM>>,
}

impl Context {
    fn init(key: &[u8], ihash: bool, ohash: bool) -> Self {
        Self {
            cipher: CIPHER_CUSTOM.create().chain_absorb(key),
            ihash: ihash.then(|| HASH_CUSTOM.create()),
            ohash: ohash.then(|| HASH_CUSTOM.create()),
        }
    }

    fn next(&mut self, buf: &mut [u8]) {
        self.ihash.as_mut().map(|ctx| ctx.absorb(buf));
        self.cipher.squeeze_xor(buf);
        self.ohash.as_mut().map(|ctx| ctx.absorb(buf));
    }

    fn finish<const N: usize>(self) -> HashResult<N> {
        HashResult {
            ihash: self.ihash.and_then(|mut ctx| Some(ctx.squeeze_to_array())),
            ohash: self.ohash.and_then(|mut ctx| Some(ctx.squeeze_to_array())),
        }
    }
}

struct HashResult<const N: usize> {
    ihash: Option<[u8; N]>,
    ohash: Option<[u8; N]>,
}

impl<const N: usize> std::fmt::Display for HashResult<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        if let Some(ihash) = self.ihash {
            f.write_str("input  hash: ")?;
            f.write_str(&hex::encode(ihash))?;
            f.write_str("\n")?;
        };
        if let Some(ohash) = self.ohash {
            f.write_str("output hash: ")?;
            f.write_str(&hex::encode(ohash))?;
            f.write_str("\n")?;
        };
        Ok(())
    }
}

use std::{num::NonZeroUsize, fs::OpenOptions, io::{Read, Write}, path::PathBuf};
use indicatif::ProgressBar;

#[derive(argh::FromArgs)]
/// shakenc
struct Args {
    /// key (if not provided in arguments, you will need to enter them later)
    #[argh(option, short = 'k')]
    key: Option<String>,
    /// buffer size (MB, default 16MB, will take this size of runtime memory)
    #[argh(option)]
    buf: Option<NonZeroUsize>,
    #[argh(subcommand)]
    sub: Commands,
}

#[derive(argh::FromArgs)]
#[argh(subcommand)]
enum Commands {
    Crypt(Crypt),
    Rng(Rng),
    Rnv(Rnv),
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "crypt")]
/// cSHAKE256 as a stream cipher for file encrypt/decrypt
struct Crypt {
    /// input file path
    #[argh(option, short = 'i')]
    input: PathBuf,
    /// output file path
    #[argh(option, short = 'o')]
    output: PathBuf,
    /// hash input file
    #[argh(switch)]
    ih: bool,
    /// hash output file
    #[argh(switch)]
    oh: bool,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "rng")]
/// cSHAKE256 as a reproduceable random generator
struct Rng {
    /// output file path
    #[argh(option, short = 'o')]
    output: PathBuf,
    /// output file length (MB)
    #[argh(option, short = 'l')]
    len: u64,
}

#[derive(argh::FromArgs)]
#[argh(subcommand, name = "rnv")]
/// cSHAKE256 as a reproduceable random generator
struct Rnv {
    /// input file path
    #[argh(option, short = 'i')]
    input: PathBuf,
}

fn main() {
    let Args { key, buf: buf_len, sub } = argh::from_env();

    let key = key.unwrap_or_else(|| rpassword::prompt_password("key: ").unwrap());
    let buf_len = buf_len.map(NonZeroUsize::get).unwrap_or(16) * 1048576;
    let mut buf = vec![0u8; buf_len];

    match sub {
        Commands::Crypt(Crypt { input, output, ih: ihash, oh: ohash }) => {
            let mut ctx = Context::init(key.as_bytes(), ihash, ohash);
            let mut input = OpenOptions::new().read(true).open(input).unwrap();
            let mut output = OpenOptions::new().create_new(true).write(true).open(output).unwrap();
            let len = input.metadata().unwrap().len();
            let mut progress = 0;
            let progress_bar = ProgressBar::new(len);

            loop {
                let read_len = input.read(&mut buf).unwrap();
                if read_len != 0 {
                    // buf == buf[..read_len] when buf_len == read_len
                    let buf = &mut buf[..read_len];
                    ctx.next(buf);
                    output.write_all(buf).unwrap();
                    progress += usize_u64(read_len);
                    progress_bar.inc(usize_u64(read_len));
                } else {
                    // must be EOF beacuse buf_len != 0
                    assert_eq!(progress, len);
                    println!("{}", ctx.finish::<32>());
                    break;
                }
            }
        },

        Commands::Rng(Rng { output, len }) => {
            let mut ctx = RAND_CUSTOM.create().chain_absorb(key.as_bytes());
            let mut output = OpenOptions::new().create_new(true).write(true).open(output).unwrap();
            let len = len * 1048576;
            let mut progress = 0;
            let progress_bar = ProgressBar::new(len);

            loop {
                if (len - progress) != 0 {
                    let write_len = buf_len.min(u64_usize(len - progress));
                    let buf = &mut buf[..write_len];
                    ctx.squeeze(buf);
                    output.write_all(buf).unwrap();
                    progress += usize_u64(write_len);
                    progress_bar.inc(usize_u64(write_len));
                } else {
                    assert_eq!(progress, len);
                    break;
                }
            }
        },

        Commands::Rnv(Rnv { input }) => {
            let mut ctx = RAND_CUSTOM.create().chain_absorb(key.as_bytes());
            let mut input = OpenOptions::new().read(true).open(input).unwrap();
            let len = input.metadata().unwrap().len();
            let mut progress = 0;
            let progress_bar = ProgressBar::new(len);
            
            loop {
                let read_len = input.read(&mut buf).unwrap();
                if read_len != 0 {
                    // buf == buf[..read_len] when buf_len == read_len
                    let buf = &mut buf[..read_len];
                    ctx.squeeze_xor(buf);
                    for (pos, b) in buf.into_iter().enumerate() {
                        if *b != 0 {
                            println!("error occurred at byte {}", progress + usize_u64(pos));
                        }
                    }
                    progress += usize_u64(read_len);
                    progress_bar.inc(usize_u64(read_len));
                } else {
                    // must be EOF beacuse buf_len != 0
                    assert_eq!(progress, len);
                    break;
                }
            }
        },
    }
}
