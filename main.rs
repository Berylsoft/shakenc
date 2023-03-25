use tiny_keccak::{CShake, Hasher as _, Xof as _};

const CIPHER_CUSTOM: &str = "__shakenc__file-stream-cipher";
const HASH_CUSTOM: &str = "__shakenc__file-hash";

struct CipherContext {
    cipher: CShake,
}

impl CipherContext {
    fn init(key: &[u8]) -> Self {
        let mut cipher = CShake::v256(&[], CIPHER_CUSTOM.as_bytes());
        cipher.update(key);
        Self { cipher }
    }

    fn next(&mut self, ibuf: &[u8], obuf: &mut [u8]) {
        assert_eq!(ibuf.len(), obuf.len());
        self.cipher.squeeze(obuf);
        for i in 0..ibuf.len() {
            obuf[i] ^= ibuf[i];
        }
    }
}

struct HashContext {
    hash: CShake
}

impl HashContext {
    fn init() -> Self {
        let hash = CShake::v256(&[], HASH_CUSTOM.as_bytes());
        Self { hash }
    }

    fn next(&mut self, buf: &[u8]) {
        self.hash.update(buf)
    }

    fn finish<const N: usize>(self) -> [u8; N] {
        let mut hash = [0; N];
        self.hash.finalize(&mut hash);
        hash
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

    fn next(&mut self, ibuf: &[u8], obuf: &mut [u8]) {
        self.cipher.next(ibuf, obuf);
        if let Some(ctx) = self.ihash.as_mut() { ctx.next(ibuf) }
        if let Some(ctx) = self.ohash.as_mut() { ctx.next(obuf) }
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
        /// buffer size (MB, default 16MB, will take twice this size of runtime memory)
        #[argh(option)]
        buf: Option<usize>,
        /// hash input file
        #[argh(switch)]
        ih: bool,
        /// hash output file
        #[argh(switch)]
        oh: bool,
    }

    use std::{fs::OpenOptions, io::{Read, Write}, path::PathBuf};
    let Args { input, output, key, buf: buf_len, ih: ihash, oh: ohash } = argh::from_env();

    let buf_len = buf_len.unwrap_or(16) * 1048576;
    let key = key.unwrap_or_else(|| rpassword::prompt_password("key: ").unwrap());

    let mut ctx = Context::init(key.as_bytes(), ihash, ohash);
    let mut ibuf = vec![0u8; buf_len];
    let mut obuf = vec![0u8; buf_len];
    let mut ifile = OpenOptions::new().read(true).open(input).unwrap();
    let mut ofile = OpenOptions::new().create_new(true).write(true).open(output).unwrap();

    loop {
        let read_len = ifile.read(&mut ibuf).unwrap();
        if read_len == 0 {
            // TODO check if EOF
            println!("{}", ctx.finish::<32>());
            break;
        } else if read_len == buf_len {
            ctx.next(&ibuf, &mut obuf);
            ofile.write_all(&obuf).unwrap();
        } else {
            ctx.next(&ibuf[0..read_len], &mut obuf[0..read_len]);
            ofile.write_all(&obuf[0..read_len]).unwrap();
        }
    }
}
