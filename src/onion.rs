use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};
use base64::{engine::general_purpose::STANDARD, Engine};
use rand::{rngs::OsRng, RngCore};
use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit},
    Aes256Gcm, Key, Nonce,
};
use std::{collections::HashMap, str};

use sha2::{Sha256, Digest};

use crate::{globals, shared::IntermediaryNode};

pub fn process_onion(
    onion: &str,
    node_registry: &HashMap<String, IntermediaryNode>,
) -> Result<String, Box<dyn std::error::Error>> {
    /*
    This function is for the server to loop through its nodes and process the tulip, 
    then get the final recipient. It uses the node_registry to access nodes' secrets.
    */
    println!("In process onion");
    let current_layer = onion.to_string();
    let parts: Vec<&str> = current_layer.split('|').collect();

    let node_id = parts[0].to_string();
    let enc_sym_key = parts[1].to_string();
    let encrypted_layer = parts[2].to_string();

    let mut current_node = node_id.clone();
    let mut current_onion = encrypted_layer.clone();
    let mut curr_enc_sym_key = enc_sym_key.clone();

    println!("Initial current_node: {}", current_node);
    println!("Initial current_onion: {}", current_onion);
    println!("Initial curr_enc_sym_key: {}", curr_enc_sym_key);

    let mut current_node_obj = node_registry
        .get(&current_node)
        .ok_or("Node ID not found in registry")?;

    let mut final_recipient_id = String::new();
    let mut final_enc_sym_key = String::new();
    let mut final_encrypted_message = String::new();


    for hop_index in 0..globals::GLOBAL_INTERMED_NODES {
        let result = current_node_obj.onion_decrypt(&current_onion, &curr_enc_sym_key)?;
        let result_owned = result.to_string();

        let parts: Vec<&str> = result_owned.split('|').collect();
        if parts.len() != 3 {
            return Err("Final layer format invalid".into());
        }

        if hop_index < (globals::GLOBAL_INTERMED_NODES - 1) {
            let node_id = parts[0].to_string();
            let enc_sym_key = parts[1].to_string();
            let encrypted_layer = parts[2].to_string();

            current_node_obj = node_registry
                .get(&node_id)
                .ok_or("Next node ID not found in registry")?;

            current_node = node_id;
            curr_enc_sym_key = enc_sym_key;
            current_onion = encrypted_layer;

            println!("Current node ID: {}", current_node_obj.id);
            println!("Current onion: {}", current_onion);
            println!("Current enc_sym_key: {}", curr_enc_sym_key);
        } else {
            // Capture the final recipient data
            final_recipient_id = parts[0].to_string();
            final_enc_sym_key = parts[1].to_string();
            final_encrypted_message = parts[2].to_string();
        }
    }

    println!("Done with intermediary node decryption. Returning from process onion.");
    let result = format!(
        "{}|{}|{}",
        final_recipient_id, final_enc_sym_key, final_encrypted_message
    );
    println!("Final result from process onion: {}", result);

    Ok(result)
}





// eileen: basic onion encryption function
// next steps include adding more information in the public key enryption part. 
// right now we only include the symmetric key, next we need to include the index, current recipient, nonce, and verification hashes
pub fn onion_encrypt(
    message: &str,
    recipient_pubkey: &RsaPublicKey,
    recipient_id: &str,
    server_nodes: &[(&str, &RsaPublicKey)]
) -> Result<String, Box<dyn std::error::Error>> {

    println!("Inside Onion Encrypt");
    let mut rng = OsRng;

    // STEP 1: Start with the innermost encryption layer for the recipient
    // generate symmetric key for the recipient's layer (sym_K4)
    let sym_key4 = Aes256Gcm::generate_key(&mut rng);
    let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
    let nonce4 = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

    // encrypt message with sym_K4
    let encrypted_message = aes_gcm4.encrypt(nonce4, message.as_bytes())?;

    // Encrypt sym_K4 with the recipient's public key
    let enc_sym_key4 = recipient_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key4)?; //this is where in future edits we need to add R, A, i, y

    // Combine the innermost layer: Recipient_ID, Enc_R_PK(sym_K4), Enc_symK4(message)
    let mut layer = format!(
        "{}|{}|{}",
        recipient_id,
        STANDARD.encode(&enc_sym_key4),
        STANDARD.encode(&encrypted_message)
    );

    //println!("Initial encrypted layer for recipient: {}", layer);
    println!("Done with encrypted layer for recipient");

    // STEP 2: wrap each subsequent layer in reverse order (starting from Node 3)
    for (node_id, node_pubkey) in server_nodes.iter().rev() {
        // Generate symmetric key for the current layer
        let sym_key = Aes256Gcm::generate_key(&mut rng);
        let aes_gcm = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key));
        let nonce = Nonce::from_slice(&[0; 12]); // Constant nonce for simplicity

        // encrypt the current layer with the symmetric key
        let encrypted_layer = aes_gcm.encrypt(&nonce, layer.as_bytes())?;

        // encrypt the symmetric key with the node's public key
        let enc_sym_key = node_pubkey.encrypt(&mut rng, Pkcs1v15Encrypt, &sym_key)?;

        // combine the current layer format:
        // node ID, Enc_PK_N(sym_K), Enc_symK(layer)
        layer = format!(
            "{}|{}|{}",
            node_id,
            STANDARD.encode(&enc_sym_key),
            STANDARD.encode(&encrypted_layer)
        );
        //println!("Layer after wrapping with node {}: {}", node_id, layer);
        println!("Done wrapping with node : {}", node_id);
    }


    // FINAL layer - Add a newline here to mark the end of the onion message
    let final_onion = format!("{}\n", layer);  // Adding the newline at the very end

    // after completing all layers, `layer` now represents the fully encrypted onion
    Ok(final_onion)
}

pub fn onion_receive(
    onion: &str,
    node_seckey: &RsaPrivateKey,
) -> Result<String, Box<dyn std::error::Error>> {
    let parts: Vec<&str> = onion.split('|').collect();
                        
    if parts.len() != 3 { // Most likely does not happen
        eprintln!("Message received does not have 3 parts!");
    }

    let recipient_id = parts[0];
    let enc_sym_key4 = parts[1];
    let encrypted_message = parts[2];

    //println!("Received: recipient_id = {}, enc_sym_key4 = {}, encrypted_message = {}", recipient_id, enc_sym_key4, encrypted_message); //debug


    // step 3: decode and decrypt symmetric key with the private key
    match STANDARD.decode(enc_sym_key4) {
        Ok(enc_sym_key_bytes) => {
            //println!("Decoded symmetric key bytes: {:?}", enc_sym_key_bytes);
            println!("Decoded symmetric key bytes");
            match node_seckey.decrypt(Pkcs1v15Encrypt, &enc_sym_key_bytes) {
                Ok(sym_key4) => {
                    //println!("Decrypted symmetric key: {:?}", sym_key4);
                    println!("Decrypted symmetric key");
                    // step 4: use the symmetric key to decrypt the message
                    let aes_gcm4 = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&sym_key4));
                    let nonce4 = Nonce::from_slice(&[0; 12]); // Same nonce as used in encryption
    
                    // decode encrypted message and do error checking
                    match STANDARD.decode(encrypted_message) {
                        Ok(encrypted_message_bytes) => {
                            //println!("Decoded encrypted message: {:?}", encrypted_message_bytes);
                            println!("Decoded encrypted message");
                            match aes_gcm4.decrypt(nonce4, encrypted_message_bytes.as_ref()) {
                                Ok(decrypted_message) => {
                                    // convert decrypted message to string and print
                                    let message_text = String::from_utf8_lossy(&decrypted_message);
                                    println!("Decrypted message: {}", message_text);
                                    // Here, you can return the decrypted message or a successful result
                                    Ok(message_text.to_string())  // Example return
                                },
                                Err(e) => {
                                    eprintln!("Failed to decrypt message: {}", e);
                                    Err(Box::new(e))  // Propagate error
                                },
                            }
                        },
                        Err(e) => {
                            eprintln!("Failed to decode encrypted message: {}", e);
                            Err(Box::new(e))  // Propagate error
                        },
                    }
                },
                Err(e) => {
                    eprintln!("Failed to decrypt symmetric key: {}", e);
                    Err(Box::new(e))  // Propagate error
                },
            }
        },
        Err(e) => {
            eprintln!("Failed to decode encrypted symmetric key: {}", e);
            Err(Box::new(e))  // Propagate error
        },
    }
    
}