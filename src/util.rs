//! age model — crypto tool.

#[derive(Debug, Clone)]
pub struct Key {
    pub name: String,
    pub fingerprint: String,
    pub created: u64,
}

#[derive(Debug, Clone)]
pub struct Signature {
    pub key: String,
    pub message: String,
    pub verified: bool,
}

#[derive(Debug, Clone)]
pub struct Model {
    pub keys: Vec<Key>,
    pub signatures: Vec<Signature>,
}

impl Default for Model {
    fn default() -> Self { Self { keys: vec![], signatures: vec![] } }
}

impl Model {
    pub fn new() -> Self { Self::default() }

    pub fn generate(&mut self, name: &str, fingerprint: &str) -> usize {
        let id = self.keys.len();
        self.keys.push(Key { name: name.into(), fingerprint: fingerprint.into(), created: 0 });
        id
    }

    pub fn sign(&mut self, key: &str, message: &str) {
        self.signatures.push(Signature { key: key.into(), message: message.into(), verified: true });
    }

    pub fn verify(&mut self, key: &str, message: &str) -> bool {
        if let Some(s) = self.signatures.iter_mut().find(|s| s.key == key && s.message == message) {
            s.verified = true;
            return true;
        }
        false
    }

    pub fn keys(&self) -> &[Key] { &self.keys }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn key_sign_verify() {
        let mut m = Model::new();
        m.generate("alice", "AA11BB22");
        m.sign("alice", "hello");
        assert!(m.verify("alice", "hello"));
    }
}
