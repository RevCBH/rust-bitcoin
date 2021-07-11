pub(crate) mod blake2b {
  use blake2::digest::{Update, VariableOutput};
  use blake2::{VarBlake2b};

  pub fn digest512(bytes: &Vec<u8>) -> Vec<u8> {
    let mut hasher = VarBlake2b::new(64).unwrap();
    hasher.update(bytes);
    let mut result: Vec<u8> = vec![0; 64];
    hasher.finalize_variable(|res| {
      result.clone_from_slice(res)
    });

    return result;
  }
}

pub(crate) mod sha3 {
  use sha3::{Digest, Sha3_256};
  pub fn multi(data: Vec<&Vec<u8>>) -> Vec<u8> {
    let mut hasher = Sha3_256::new();
    for d in data {
      hasher.update(d);
    }

    return hasher.finalize().to_vec();
  }
}