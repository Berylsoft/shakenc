fn once(key: &[u8], bytes: &[u8]) -> Vec<u8> {
    use tiny_keccak::{Shake, Hasher, Xof};
    let mut hasher = Shake::v256();
    hasher.update(key);
    let mut output = vec![0; bytes.len()];
    hasher.squeeze(&mut output);
    for i in 0..bytes.len() {
        output[i] = output[i] ^ bytes[i];
    }
    output
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

    use std::{fs::{read, write}, path::PathBuf};
    let Args { input, output, key } = argh::from_env();
    write(output, once(key.as_bytes(), &read(input).unwrap())).unwrap();
}
