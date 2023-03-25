use tiny_keccak::{CShake, Hasher as _, Xof as _};

const CIPHER_CUSTOM: &str = "__shakenc__file-stream-cipher";
const HASH_CUSTOM: &str = "__shakenc__file-hash";

struct Context {
    cipher: CShake,
    ihash: Option<CShake>,
    ohash: Option<CShake>,
}

fn init_hash() -> CShake {
    CShake::v256(&[], HASH_CUSTOM.as_bytes())
}

fn finish_hash<const N: usize>(hasher: CShake) -> Option<[u8; N]> {
    let mut hash = [0; N];
    hasher.finalize(&mut hash);
    Some(hash)
}

impl Context {
    fn init(key: &[u8], ihash: bool, ohash: bool) -> Self {
        let mut cipher = CShake::v256(&[], CIPHER_CUSTOM.as_bytes());
        cipher.update(key);
        let ihash = ihash.then(init_hash);
        let ohash = ohash.then(init_hash);
        Self { cipher, ihash, ohash }
    }

    fn next(&mut self, ibuf: &[u8], obuf: &mut [u8]) {
        assert_eq!(ibuf.len(), obuf.len());
        self.ihash.as_mut().and_then(|hasher| Some(hasher.update(ibuf)));
        self.ohash.as_mut().and_then(|hasher| Some(hasher.update(obuf)));
        self.cipher.squeeze(obuf);
        for i in 0..ibuf.len() {
            obuf[i] ^= ibuf[i];
        }
    }

    fn finish<const N: usize>(self) -> HashResult<N> {
        HashResult {
            ihash: self.ihash.and_then(finish_hash::<N>),
            ohash: self.ohash.and_then(finish_hash::<N>),
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
