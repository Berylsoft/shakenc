use std::num::NonZeroUsize;

use cshake::{CShake, CShakeCustom, cshake_customs, Absorb, Squeeze, SqueezeXor};

cshake_customs!{
    CIPHER_CUSTOM -> "__shakenc__file-stream-cipher"
    HASH_CUSTOM -> "__shakenc__file-hash"
}

struct CipherContext {
    cipher: CShake<CIPHER_CUSTOM>,
}

impl CipherContext {
    fn init(key: &[u8]) -> Self {
        let mut cipher = CIPHER_CUSTOM.create();
        cipher.absorb(key);
        Self { cipher }
    }

    fn next(&mut self, buf: &mut [u8]) {
        self.cipher.squeeze_xor(buf);
    }
}

struct HashContext {
    hash: CShake<HASH_CUSTOM>,
}

impl HashContext {
    fn init() -> Self {
        let hash = HASH_CUSTOM.create();
        Self { hash }
    }

    fn next(&mut self, buf: &[u8]) {
        self.hash.absorb(buf)
    }

    fn finish<const N: usize>(mut self) -> [u8; N] {
        self.hash.squeeze_to_array()
    }
}

struct Context {
    cipher: CipherContext,
    ihash: Option<HashContext>,
    ohash: Option<HashContext>,
}

impl Context {
    fn init(key: &[u8], ihash: bool, ohash: bool) -> Self {
        let cipher = CipherContext::init(key);
        let ihash = ihash.then(|| HashContext::init());
        let ohash = ohash.then(|| HashContext::init());
        Self { cipher, ihash, ohash }
    }

    fn next(&mut self, buf: &mut [u8]) {
        if let Some(ctx) = self.ihash.as_mut() { ctx.next(buf) }
        self.cipher.next(buf);
        if let Some(ctx) = self.ohash.as_mut() { ctx.next(buf) }
    }

    fn finish<const N: usize>(self) -> HashResult<N> {
        HashResult {
            ihash: self.ihash.and_then(|ctx| Some(ctx.finish::<N>())),
            ohash: self.ohash.and_then(|ctx| Some(ctx.finish::<N>())),
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

fn main() {
    #[derive(argh::FromArgs)]
    /// shakenc: cSHAKE256 as a stream cipher for file encrypt/decrypt
    struct Args {
        /// input file path
        #[argh(option, short = 'i')]
        input: PathBuf,
        /// output file path
        #[argh(option, short = 'o')]
        output: PathBuf,
        /// key (if not provided in arguments, you will need to enter them later)
        #[argh(option, short = 'k')]
        key: Option<String>,
        /// buffer size (MB, default 16MB, will take this size of runtime memory)
        #[argh(option)]
        buf: Option<NonZeroUsize>,
        /// hash input file
        #[argh(switch)]
        ih: bool,
        /// hash output file
        #[argh(switch)]
        oh: bool,
    }

    use std::{fs::OpenOptions, io::{Read, Write}, path::PathBuf};
    let Args { input, output, key, buf: buf_len, ih: ihash, oh: ohash } = argh::from_env();

    let buf_len = buf_len.map(NonZeroUsize::get).unwrap_or(16) * 1048576;
    let key = key.unwrap_or_else(|| rpassword::prompt_password("key: ").unwrap());

    let mut ctx = Context::init(key.as_bytes(), ihash, ohash);
    let mut buf = vec![0u8; buf_len];
    let mut input = OpenOptions::new().read(true).open(input).unwrap();
    let mut output = OpenOptions::new().create_new(true).write(true).open(output).unwrap();

    loop {
        match input.read(&mut buf).unwrap() {
            0 => {
                // must be EOF beacuse buf_len != 0
                println!("{}", ctx.finish::<32>());
                break;
            },
            read_len if read_len == buf_len => {
                ctx.next(&mut buf);
                output.write_all(&buf).unwrap();
            },
            read_len => {
                ctx.next(&mut buf[0..read_len]);
                output.write_all(&buf[0..read_len]).unwrap();
            },
        }
    }
}
