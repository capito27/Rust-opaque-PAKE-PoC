use std::io::prelude::*;
use std::net::TcpStream;
use sha3::Digest;
use hex::ToHex;
use opaque::types::CtxClient;
use opaque::client::{client_init_login_bytes, client_validate_bytes};
use std::io;
use std::process::exit;

fn main() {
    let socket = match TcpStream::connect("127.0.0.1:7878") {
        Ok(sock) => sock,
        Err(_) => {
            eprintln!("Could not connect to remote target");
            exit(-1);
        }
    };
    handle_connection(&socket);


    println!("Shutting down.");
}

fn handle_connection(stream: &TcpStream) {
    loop {
        let mut string = String::new();
        println!("Welcome, please type 1 to register, 2 to login or q to exit :");
        io::stdin().read_line(&mut string).unwrap();
        match string.trim() {
            "1" => register_handler(&stream),
            "2" => login_handler(&stream),
            "q" => break,
            _ => continue,
        };
    }
}

fn username_to_sid(username: &[u8]) -> String {
    let mut hasher = sha3::Sha3_256::new();
    hasher.input(username);
    return hasher.result().encode_hex();
}

fn register_handler(mut stream: &TcpStream) {
    loop {
        let mut buffer = [0; 1024];
        let mut username = String::new();
        let mut password = String::new();

        println!("Please, write your username (at least 5 characters) or q to exit :");
        io::stdin().read_line(&mut username).unwrap();
        match username.trim() {
            "q" => break,
            _ => { if username.len() < 6 { continue; } }
        };


        println!("Please, write your password (at least 6 characters) or q to exit :");

        io::stdin().read_line(&mut password).unwrap();
        match password.trim() {
            "q" => break,
            _ => { if password.len() < 7 { continue; } }
        };

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        match stream.write(b"1\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        match stream.write(username.as_bytes()) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        match stream.write(password.as_bytes()) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        // Print server reply
        match stream.read(&mut buffer) {
            Ok(s) => println!("{}", String::from_utf8(buffer[..s].to_vec()).unwrap()),
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        break;
    }
}

fn login_handler(mut stream: &TcpStream) {
    loop {
        let mut buffer = [0; 1024];
        let mut username = String::new();
        let mut password = String::new();

        println!("Please, write your username (at least 5 characters) or q to exit :");
        io::stdin().read_line(&mut username).unwrap();
        match username.trim() {
            "q" => break,
            _ => { if username.len() < 6 { continue; } }
        };

        let sid = username_to_sid(username.as_bytes());
        println!("Please, write your password (at least 6 characters) or q to exit :");

        io::stdin().read_line(&mut password).unwrap();
        match password.trim() {
            "q" => break,
            _ => { if password.len() < 7 { continue; } }
        };

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        match stream.write(b"2\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        match stream.write(username.as_bytes()) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        // Drop buffer contents
        match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        let mut client_ctx = CtxClient::new(sid.as_str());

        let client_init = match client_init_login_bytes(&mut client_ctx, password.as_str()) {
            Ok(t) => t,
            Err(_) => {
                println!("Login failed at step 1 of 4 ! (unexpected error)\n");
                match stream.write(b"q\n") {
                    Ok(s) => s,
                    _ => {
                        eprintln!("Server closed connection unexpectedly");
                        break;
                    }
                };
                continue;
            }
        };

        match stream.write(&client_init) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        let size = match stream.read(&mut buffer) {
            Ok(s) => {
                if s == 1 && buffer[0] == b'q' {
                    println!("Login failed at step 2 of 4 ! (unknown username)\n");
                    continue;
                }
                if s < 268 {
                    eprintln!("Server sent too little data, aborting");
                    match stream.write(b"q\n") {
                        Ok(s) => s,
                        _ => {
                            eprintln!("Server closed connection unexpectedly");
                            break;
                        }
                    };
                    stream.flush().unwrap();
                    break;
                }
                s
            }
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };

        // The client is now able to validate the server identity and compute the shared key
        let client_validate = match client_validate_bytes(&mut client_ctx, password.as_str(), &buffer[..size]) {
            Ok(t) => t,
            Err(_) => {
                println!("Login failed at step 3 of 4 ! (incorrect password)\n");
                match stream.write(b"q") {
                    Ok(s) => s,
                    _ => {
                        eprintln!("Server closed connection unexpectedly");
                        break;
                    }
                };
                stream.flush().unwrap();
                continue;
            }
        };

        match stream.write(&client_validate) {
            Ok(s) => s,
            _ => {
                eprintln!("Server closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        let sk: String = client_ctx.get_shared_key().unwrap().encode_hex();
        println!("Login successful !\nHere is the shared secret :{}\n", sk.as_str());
        stream.flush().unwrap();
        break;
    }
}