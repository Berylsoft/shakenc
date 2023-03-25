use tiny_keccak::{CShake, Hasher as _, Xof as _};

struct Context {
    cipher: CShake,
    ihash: CShake,
    ohash: CShake,
}

const CIPHER_CUSTOM: &str = "__shakenc__file-stream-cipher";
const HASH_CUSTOM: &str = "__shakenc__file-hash";

impl Context {
    fn init(key: &[u8]) -> Self {
        let mut cipher = CShake::v256(&[], CIPHER_CUSTOM.as_bytes());
        cipher.update(key);
        let ihash = CShake::v256(&[], HASH_CUSTOM.as_bytes());
        let ohash = CShake::v256(&[], HASH_CUSTOM.as_bytes());
        Self { cipher, ihash, ohash }
    }

    fn next(&mut self, ibuf: &[u8], obuf: &mut [u8]) {
        assert_eq!(ibuf.len(), obuf.len());
        self.ihash.update(ibuf);
        self.ohash.update(obuf);
        self.cipher.squeeze(obuf);
        for i in 0..ibuf.len() {
            obuf[i] ^= ibuf[i];
        }
    }

    fn finish<const N: usize>(self) -> ([u8; N], [u8; N]) {
        let mut ihash = [0; N];
        let mut ohash = [0; N];
        self.ihash.finalize(&mut ihash);
        self.ohash.finalize(&mut ohash);
        (ihash, ohash)
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
    }

    use std::{fs::OpenOptions, io::{Read, Write}, path::PathBuf};
    let Args { input, output, key, buf: buf_len } = argh::from_env();

    let buf_len = buf_len.unwrap_or(16) * 1048576;
    let key = key.unwrap_or_else(|| rpassword::prompt_password("key: ").unwrap());

    let mut ctx = Context::init(key.as_bytes());
    let mut ibuf = vec![0u8; buf_len];
    let mut obuf = vec![0u8; buf_len];
    let mut ifile = OpenOptions::new().read(true).open(input).unwrap();
    let mut ofile = OpenOptions::new().create_new(true).write(true).open(output).unwrap();

    loop {
        let read_len = ifile.read(&mut ibuf).unwrap();
        if read_len == 0 {
            // TODO check if EOF
            let (ihash, ohash) = ctx.finish::<32>();
            println!("input  hash: {}", hex::encode(ihash));
            println!("output hash: {}", hex::encode(ohash));
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
