use tiny_keccak::{Shake, Hasher, Xof};

fn init(key: &[u8]) -> Shake {
    let mut ctx = Shake::v256();
    ctx.update(key);
    ctx
}

fn once<const N: usize>(ctx: &mut Shake, ibuf: &[u8; N], obuf: &mut [u8; N]) {
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
    }

    use std::{fs::OpenOptions, io::{Read, Write}, path::PathBuf};
    let Args { input, output, key } = argh::from_env();

    let mut ctx = init(key.as_bytes());
    let mut input = OpenOptions::new().read(true).open(input).unwrap();
    let mut output = OpenOptions::new().read(true).open(output).unwrap();

    const BUF_LEN: usize = 16384;
    let mut ibuf = [0; BUF_LEN];
    let mut obuf = [0; BUF_LEN];

    input.read_exact(&mut ibuf).unwrap();
    once(&mut ctx, &ibuf, &mut obuf);
    output.write_all(&obuf).unwrap();
}
