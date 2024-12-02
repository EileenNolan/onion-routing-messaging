use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};


// implement shared.rs because dependencies weren't working if I just used intermediary_node.rs for some reason
// use shared.rs to prevent circular dependencies (which rust doens't like..?)

use base64::{engine::general_purpose::STANDARD, Engine};
use aes_gcm::{
    aead::{Aead, KeyInit}, Aes256Gcm, Key, Nonce
};
use std::{collections::HashMap, str};

use sha2::{Sha256, Digest};

use std::error::Error;
// shared.rs
pub struct IntermediaryNode {
    pub id: String,
    pub public_key: RsaPublicKey,
    pub private_key: RsaPrivateKey,
}

// has it's own id, public, and private key
impl IntermediaryNode {
    // Constructor method to create a new IntermediaryNode
    pub fn new(id: &str, public_key: RsaPublicKey, private_key: RsaPrivateKey) -> Self {
        IntermediaryNode {
            id: id.to_string(),
            public_key,
            private_key,
        }
    }

    //intermediary node uses this to decrypt
    // eileen function to decrypt the onion received from client
    pub fn onion_decrypt(
        &self,
        onion: &str,
        enc_layer: &str,
     // Maps node IDs to their private keys
    ) -> Result<String, Box<dyn Error>> {
        let mut current_layer = onion.to_string();

        // get the private key for the current node
        let node_seckey = &self.private_key;
        let enc_sym_key = enc_layer;
        // Decrypt the symmetric key for the current layer using the current node's private key
        let enc_sym_key_bytes = STANDARD.decode(enc_sym_key)?;
        let sym_key_bytes = node_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes)?;

        // decrypt the layer content using the symmetric key for the current layer
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key_bytes));
        let nonce = Nonce::from_slice(&[0; 12]); // Use a constant nonce

        let decrypted_layer = aes_gcm.decrypt(nonce, &*STANDARD.decode(onion)?)?;

        // Convert the decrypted layer back to a string for the next iteration
        current_layer = String::from_utf8_lossy(&decrypted_layer).into_owned();

            //println!("Current layer after decryption: {}", current_layer); //debugging

        Ok(current_layer) // Return the formatted string to the client
    }
    
}