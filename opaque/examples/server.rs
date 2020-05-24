use std::io::prelude::*;
use std::net::TcpListener;
use std::net::TcpStream;
use threadpool::ThreadPool;
use sha3::Digest;
use opaque::server::{register, server_init_login_bytes, server_validate_bytes};
use hex::ToHex;
use opaque::types::CtxServer;

fn main() {
    let listener = TcpListener::bind("127.0.0.1:7878").unwrap();
    let n_workers = 4;
    let pool = ThreadPool::new(n_workers);

    for stream in listener.incoming() {
        let stream = stream.unwrap();
        pool.execute(move || {
            handle_connection(&stream);
        });
    }

    println!("Shutting down.");
}

fn handle_connection(mut stream: &TcpStream) {
    loop {
        let mut buffer = [0; 1024];
        match stream.write(b"Welcome, please send 1 to register, 2 to login or q to exit :\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };
        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
        };
        if size != 2 || ![b"1", b"2", b"q"].contains(&&[buffer[0]]) {
            continue;
        }

        match buffer[0] {
            b'1' => register_handler(&stream),
            b'2' => login_handler(&stream),
            b'q' | _ => break,
        };

        match stream.flush() {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
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
        match stream.write(b"Please, write your username (at least 5 characters) or q to exit :\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };

        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
        };

        if (size == 1 && buffer[0] != b'q') || size < 6 {
            continue;
        }

        if buffer[0] == b'q' {
            break;
        }

        let username = unsafe { String::from_utf8_unchecked(buffer[..size].to_vec()) };
        let sid = username_to_sid(username.as_bytes());

        println!("sid : {}", sid);
        match stream.write(b"Please, write your password (at least 6 characters) or q to exit :\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };

        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
        };

        if (size == 2 && buffer[0] != b'q') || size < 7 {
            continue;
        }

        if buffer[0] == b'q' {
            break;
        }


        let pw = unsafe { String::from_utf8_unchecked(buffer[..size].to_vec()) };

        register(sid.as_str(), pw.as_str());

        match stream.write(b"Registration successful !\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();
        break;
    }
}

fn login_handler(mut stream: &TcpStream) {
    loop {
        let mut buffer = [0; 1024];
        match stream.write(b"Please, write your username (at least 5 characters) or q to exit :\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };
        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
        };
        if (size == 1 && buffer[0] != b'q') || size < 6 {
            continue;
        }

        if buffer[0] == b'q' {
            break;
        }

        let username = unsafe { String::from_utf8_unchecked(buffer[..size].to_vec()) };
        let sid = username_to_sid(username.as_bytes());

        match stream.write(b"Please, send your alpha and Xu encoded or q to exit :\n") {
            Ok(s) => s,
            _ => {
                eprintln!("Client closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("Client unexpectedly disconnected");
                break;
            }
        };

        if size == 1 && buffer[0] == b'q' {
            eprintln!("Login for user \"{}\" failed at step 1 of 4 ! (unexpected error)\n", username.trim());
            break;
        }

        let mut server_ctx = CtxServer::new(sid.as_str());

        let server_init = match server_init_login_bytes(&mut server_ctx, &buffer[..size]) {
            Ok(t) => t,
            Err(_) => {
                eprintln!("Login for user \"{}\" failed at step 2 of 4 ! (unknown username)\n", username.trim());
                match stream.write(b"q") {
                    Ok(s) => s,
                    _ => {
                        eprintln!("client closed connection unexpectedly");
                        break;
                    }
                };
                continue;
            }
        };



        match stream.write(&server_init) {
            Ok(s) => s,
            _ => {
                eprintln!("client closed connection unexpectedly");
                break;
            }
        };
        stream.flush().unwrap();

        let size = match stream.read(&mut buffer) {
            Ok(s) => s,
            _ => {
                eprintln!("client closed connection unexpectedly");
                break;
            }
        };

        if size == 1 && buffer[0] == b'q' {
            println!("Login for user \"{}\" failed at step 3 of 4 ! (incorrect password)\n", username.trim());
            break;
        }

        match server_validate_bytes(&mut server_ctx, &buffer[..size]) {
            Ok(t) => t,
            Err(_) => {
                println!("Login for user \"{}\" failed at step 4 of 4 !\n", username.trim());
                match stream.write(b"q") {
                    Ok(s) => s,
                    _ => {
                        eprintln!("client closed connection unexpectedly");
                        break;
                    }
                };
                continue;
            }
        };


        let sk: String = server_ctx.get_shared_key().unwrap().encode_hex();
        println!("Login successful !\nHere is the shared secret :{}\n", sk.as_str());
        stream.flush().unwrap();
        break;
    }
}