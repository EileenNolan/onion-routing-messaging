#![allow(warnings)]
extern crate rsa;
extern crate sha2;

mod crypto;
mod intermediary_node;
mod shared;
use std::time::Instant;
mod onion;
mod globals;
use std::net::TcpStream;
use std::io::{self, Write, Read};
use std::sync::{Arc, Mutex};
use std::thread;
use chrono::Local;
use crypto::{read_pubkey_list, generate_pubkey};
use rsa::pkcs1::{DecodeRsaPublicKey, EncodeRsaPublicKey, LineEnding};
use rsa::RsaPublicKey; 
use std::collections::HashMap;
use onion::{onion_encrypt, onion_receive};


fn main() -> Result<(), Box<dyn std::error::Error>> {
    env_logger::init();
    match TcpStream::connect("127.0.0.1:7878") {
        Ok(mut stream) => {
            eprintln!("Successfully connected to server on port 7878");

            // prompt for username
            eprintln!("Enter your username:");
            let mut username = String::new();
            io::stdin().read_line(&mut username).unwrap();

            // phuoc: generate new pubkey
            let (personal_seckey, personal_pubkey) = generate_pubkey().unwrap();
            let pubkey_pem = personal_pubkey.to_pkcs1_pem(LineEnding::LF).expect("failed to encode public key to PEM");
            stream.write_all(format!("{}\n{}",username.trim(), pubkey_pem).as_bytes()).unwrap();

            // phuoc: Read the pubkey list from PKkeys.txt 
            //eileen: read and add to a hashmap for easier/faster use later
            let (server_ids, server_pubkeys) = read_pubkey_list("PKKeys.txt").expect("Failed to read server public keys from PKKeys.txt");

            // create HashMap for server nodes (server ID -> public key)
            let server_nodes = Arc::new(Mutex::new(
                server_ids.into_iter().zip(server_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
            ));
            //println!("Loaded server public keys from PKKeys.txt");

            // load existing users and their public keys from UserKeys.txt into HashMap
            let (usernames, user_pubkeys) = read_pubkey_list("UserKeys.txt").expect("Failed to read user public keys from UserKeys.txt");
            // Wrap existing_users in an Arc<Mutex<...>> for thread-safe access
            let existing_users = Arc::new(Mutex::new(
                usernames.into_iter().zip(user_pubkeys.into_iter()).collect::<HashMap<String, RsaPublicKey>>(),
            ));
            //println!("Loaded existing user public keys from UserKeys.txt");

            // ---------- RECEIVING MESSAGES ------------ //

            // spawn a thread to listen for incoming messages
            // clone Arc to move into thread
            let mut read_stream = stream.try_clone().unwrap();
            let existing_users_thread = Arc::clone(&existing_users);
            let mut start2 = Instant::now();
            thread::spawn(move || {
                let mut buffer = [0; 512];
                // ensure there is something to fetch from buffer
                while let Ok(size) = read_stream.read(&mut buffer) {
                    if size == 0 {
                        break;
                    }
            
                    let received_message = String::from_utf8_lossy(&buffer[..size]);

                    // eileen step 1: check if the message is new user broadcast
                    if let Some((new_username, new_pubkey_pem)) = parse_new_user_broadcast(&received_message) {
                        match RsaPublicKey::from_pkcs1_pem(&new_pubkey_pem) {
                            Ok(new_pubkey) => {
                                // insert new user into the existing_users HashMap
                                let mut users_lock = existing_users_thread.lock().unwrap();
                                users_lock.insert(new_username.clone(), new_pubkey);
                                //println!("Added new user {} with public key", new_username);
                            },
                            Err(e) => {
                                eprintln!("Failed to decode public key for {}: {}", new_username, e);
                            }
                        }
                    } else {
                        // eileen step 2: else it is a regular ciphertext (last layer of the onion)
                        // eileen comments on current implementation and next steps:
                        // split received message format: Recipient_ID|Enc_R_PK(sym_K4)|Enc_symK4(message)
                        // using index 4 here because we are using three intermediary nodes, so the recipient will have index 4
                        // later we will add these indexes into the metadata of the onion, specifically in the part encrypted with the public key
                        // for now this only includes the current symmetric key for the node
                        //println!("Raw received message: {}", received_message);
                        //start timer for client to decrypt their final part of onion
                        let start3 = Instant::now();
                        let result_message = onion_receive(&received_message.to_string(), &personal_seckey);
                        assert!(result_message.is_ok(), "onion_receive failed: {:?}", result_message);
                        let duration3 = start3.elapsed();
                        let duration2 = start2.elapsed();
                        //println!("TIMER RESULT: End-to-end delivery time: {:?}", duration2);
                        println!("TIMER RESULT: Time for client to decrypt final part of onion:  {:?}", duration3);
                        let message = result_message.unwrap();
                        eprintln!("Received message: {}", message);
                        let now = Local::now(); // Get the current local time
                        println!("End-to-end finish now: {}", now);
                    }
                }
            });
            
            // eileen edits to main thread loop for sending messages
            // ---------- SENDING ENCRYPTED MESSAGES ------------ //
            loop {
                eprintln!("Enter recipient:");
                let mut recipient = String::new();
                io::stdin().read_line(&mut recipient).unwrap();
                let recipient = recipient.trim().to_string();
            
                eprintln!("Enter your message:");
                let mut message = String::new();
                io::stdin().read_line(&mut message).unwrap();
                let username = username.trim().to_string();
                let no_username_message = message.trim().to_string();
                let message = format!("(from {}) {}", username, no_username_message);

                let now = Local::now(); // Get the current local time
                println!("TIMER RESULT: End-to-end start now: {}", now);


                // encrypt the initial message with a symmetric key for the recipient
                let recipient_pubkey = match existing_users.lock().unwrap().get(&recipient) {
                    Some(key) => key.clone(),
                    None => {
                        println!("Recipient's public key not found.");
                        continue;
                    }
                };

                // lock the server_nodes to safely access it
                let server_nodes_locked = server_nodes.lock().unwrap();

                // phuoc: I will just focus on tulip sampling now, I will need to delete the onion sampling code
                // select up to three mixers from server_nodes, with their IDs and public keys
                //TEST EDIT HERE NUMBER OF NODES

                if globals::GLOBAL_INTERMED_NODES > server_nodes_locked.len(){
                    return Err("Gloabl Variable of Intermediary Nodes is larger than selected intermediary nodes when running server key gen".into());
                }

                //println!("Choosing GLOBAL_INTERMED_NODES random intermediary nodes.");
                let selected_server_nodes: Vec<(&str, &RsaPublicKey)> = server_nodes_locked
                    .iter()
                    .take(globals::GLOBAL_INTERMED_NODES)  // Get the first three nodes if available
                    .map(|(id, pubkey)| (id.as_str(), pubkey))
                    .collect();


                // ensure we have exactly -- nodes for encryption
                if selected_server_nodes.len() < 1 {
                    println!("Insufficient nodes available for onion encryption.");
                    continue;
                }


                //STARTING CLIENT TIMER
                let start = Instant::now();
                start2 = Instant::now();
                // perform onion encryption using helper function defined below
                let encrypted_onion = onion_encrypt(&message, &recipient_pubkey, &recipient, &selected_server_nodes)?;
                let duration = start.elapsed();
                println!("TIMER RESULTS: Time taken to encrypt message for client: {:?}", duration);
                // send onion-encrypted message over the stream
                if let Err(e) = stream.write_all(encrypted_onion.as_bytes()) {
                    eprintln!("Failed to send message: {}", e);
                } else {
                    println!("Message sent successfully.");
                }
            }
        },
        Err(e) => {
            println!("Failed to connect: {}", e);
        }
    }

    Ok(())
}

// eileen: helper function to parse new user broadcast messages
fn parse_new_user_broadcast(message: &str) -> Option<(String, String)> {
    let mut lines = message.lines();
    let username = lines.next()?.to_string();
    let pubkey_pem = lines.collect::<Vec<_>>().join("\n");
    if pubkey_pem.contains("BEGIN RSA PUBLIC KEY") {
        Some((username, pubkey_pem))
    } else {
        None
    }
}

