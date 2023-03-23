use tiny_keccak::{Shake, Hasher, Xof};

fn init(key: &[u8]) -> Shake {
    let mut ctx = Shake::v256();
    ctx.update(key);
    ctx
}

fn once(ctx: &mut Shake, ibuf: &[u8], obuf: &mut [u8]) {
    assert_eq!(ibuf.len(), obuf.len());
    ctx.squeeze(obuf);
    for i in 0..ibuf.len() {
        obuf[i] = obuf[i] ^ ibuf[i];
    }
}

fn main() {
    #[derive(argh::FromArgs)]
    /// shake256 file encrypt/decrypt
    struct Args {
        /// input file path
        #[argh(option, short = 'i')]
        input: PathBuf,
        /// output file path
        #[argh(option, short = 'o')]
        output: PathBuf,
        /// key
        #[argh(option, short = 'k')]
        key: String,
        /// buffer size (KB, default 16KB, will take twice this size of runtime memory)
        #[argh(option)]
        buf: Option<usize>,
    }

    use std::{fs::OpenOptions, io::{Read, Write}, path::PathBuf};
    let Args { input, output, key, buf: buf_len } = argh::from_env();

    let mut ctx = init(key.as_bytes());
    let mut input = OpenOptions::new().read(true).open(input).unwrap();
    let mut output = OpenOptions::new().read(true).open(output).unwrap();
    let buf_len = buf_len.and_then(|n| Some(n * 1024)).unwrap_or(16384);
    let mut ibuf = vec![0u8; buf_len];
    let mut obuf = vec![0u8; buf_len];

    input.read_exact(&mut ibuf).unwrap();
    once(&mut ctx, &ibuf, &mut obuf);
    output.write_all(&obuf).unwrap();
}
