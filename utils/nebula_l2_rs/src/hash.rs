use serde_json::Value;
use sha3::{
    digest::{ExtendableOutput, Update, XofReader},
    Shake256,
};

pub enum HashPart<'a> {
    Bytes(&'a [u8]),
    Str(&'a str),
    U64(u64),
    Int(i128),
    Json(&'a Value),
}

fn canonical_json(value: &Value) -> String {
    match value {
        Value::Null => "null".to_string(),
        Value::Bool(value) => value.to_string(),
        Value::Number(value) => value.to_string(),
        Value::String(value) => serde_json::to_string(value).expect("string serialization"),
        Value::Array(values) => {
            let items = values.iter().map(canonical_json).collect::<Vec<_>>();
            format!("[{}]", items.join(","))
        }
        Value::Object(values) => {
            let mut keys = values.keys().collect::<Vec<_>>();
            keys.sort();
            let items = keys
                .into_iter()
                .map(|key| {
                    let encoded_key = serde_json::to_string(key).expect("key serialization");
                    let encoded_value = canonical_json(&values[key]);
                    format!("{encoded_key}:{encoded_value}")
                })
                .collect::<Vec<_>>();
            format!("{{{}}}", items.join(","))
        }
    }
}

pub fn canonical_json_string(value: &Value) -> String {
    canonical_json(value)
}

pub fn json_size(value: &Value) -> usize {
    canonical_json(value).len()
}

fn encode_part(part: &HashPart<'_>) -> Vec<u8> {
    match part {
        HashPart::Bytes(value) => value.to_vec(),
        HashPart::Str(value) => value.as_bytes().to_vec(),
        HashPart::U64(value) => value.to_string().into_bytes(),
        HashPart::Int(value) => value.to_string().into_bytes(),
        HashPart::Json(value) => canonical_json(value).into_bytes(),
    }
}

pub fn domain_hash(domain: &str, parts: &[HashPart<'_>], out_len: usize) -> String {
    let mut shake = Shake256::default();
    shake.update(b"NEBULA-L2-DEVNET\0");
    shake.update(domain.as_bytes());
    shake.update(b"\0");
    for part in parts {
        let encoded = encode_part(part);
        shake.update(&(encoded.len() as u64).to_be_bytes());
        shake.update(&encoded);
    }
    let mut reader = shake.finalize_xof();
    let mut output = vec![0_u8; out_len];
    reader.read(&mut output);
    hex::encode(output)
}

pub fn merkle_root(domain: &str, leaves: &[Value]) -> String {
    let mut level = leaves
        .iter()
        .map(|leaf| {
            let leaf_domain = format!("{domain}:leaf");
            match leaf {
                Value::String(value) => domain_hash(&leaf_domain, &[HashPart::Str(value)], 32),
                Value::Number(value) => {
                    if let Some(value) = value.as_i64() {
                        domain_hash(&leaf_domain, &[HashPart::Int(value as i128)], 32)
                    } else if let Some(value) = value.as_u64() {
                        domain_hash(&leaf_domain, &[HashPart::Int(value as i128)], 32)
                    } else {
                        domain_hash(&leaf_domain, &[HashPart::Json(leaf)], 32)
                    }
                }
                _ => domain_hash(&leaf_domain, &[HashPart::Json(leaf)], 32),
            }
        })
        .collect::<Vec<_>>();
    if level.is_empty() {
        return domain_hash(&format!("{domain}:empty"), &[], 32);
    }

    while level.len() > 1 {
        let mut next = Vec::with_capacity(level.len().div_ceil(2));
        for chunk in level.chunks(2) {
            let left = chunk[0].as_str();
            let right = chunk.get(1).map(String::as_str).unwrap_or(left);
            next.push(domain_hash(
                &format!("{domain}:node"),
                &[HashPart::Str(left), HashPart::Str(right)],
                32,
            ));
        }
        level = next;
    }
    level[0].clone()
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn domain_hash_matches_python_reference_vector() {
        let payload = json!({"z": 1, "a": true});
        assert_eq!(
            domain_hash(
                "GO-PARITY",
                &[
                    HashPart::Str("alpha"),
                    HashPart::Int(7),
                    HashPart::Json(&payload)
                ],
                32,
            ),
            "922e765ff725965ef4ede8e2f21cf6c08d2a22ddefd07f1cd4b67e522b893d83"
        );
    }
}
