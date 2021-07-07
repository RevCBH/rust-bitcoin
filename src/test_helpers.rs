#[cfg(test)]
pub(crate) mod tests {
    use crate::consensus::{encode::deserialize, Decodable};
    use hashes::hex::FromHex;
    use serde::de;
    use std::{fs, path::PathBuf};

    pub fn fixture_json<T: de::DeserializeOwned>(
        name: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        let contents = fs::read_to_string(d)?;
        let result: T = serde_json::from_str(contents.as_str())?;

        Ok(result)
    }

    pub fn fixture_hex<T: de::DeserializeOwned + Decodable>(
        name: &str,
    ) -> Result<T, Box<dyn std::error::Error>> {
        let d = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("fixtures")
            .join(name);
        let hex = fs::read_to_string(d)?;

        let result: T = deserialize(&Vec::<u8>::from_hex(hex.as_str())?)?;

        Ok(result)
    }
}
