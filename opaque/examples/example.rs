use std::process::exit;
use std::time::Instant;

use opaque::types::*;
use opaque::server::*;
use opaque::client::*;

fn main() {
    let mut client_ctx = CtxClient::new("toto");
    let mut server_ctx = CtxServer::new("toto");

    register("toto", "titi");
    let now = Instant::now();
    // client doesn't know the value of session id yet, simply computes a couple points for the server
    // and initializes the context
    let client_init = match client_init_login(&mut client_ctx, "titi") {
        Ok(t) => t,
        Err(_) => exit(-1),
    };

    println!("client init duration : {} ms", now.elapsed().as_millis());
    let tmp = Instant::now();

    // Client transmits the 2 points to the server

    // server init a bunch of stuff, along with the session id
    let server_init = match server_init_login(&mut server_ctx, &client_init.0, &client_init.1) {
        Ok(t) => t,
        Err(_) => exit(-1),
    };

    println!("server init duration : {} ms", tmp.elapsed().as_millis());
    let tmp = Instant::now();


    // Server transmits some data to client, including the session id
    client_ctx.set_ssid(&server_ctx.get_ssid());

    // The client is now able to validate the server identity and compute the shared key
    let client_validate = match client_validate(&mut client_ctx, &server_init.0, &server_init.1, &server_init.2, &server_init.3, &server_init.4, "titi") {
        Ok(t) => t,
        Err(_) => exit(-1)
    };

    println!("client validate duration : {} ms", tmp.elapsed().as_millis());
    let tmp = Instant::now();

    // The client finally transmits to the server a proof of knowledge

    // The server can now validate the client identity
    match server_validate(&mut server_ctx, &client_validate) {
        Ok(t) => t,
        Err(_) => exit(-1)
    };

    println!("server validate duration : {} ms", tmp.elapsed().as_millis());


    println!("Successful login, here is the final shared key :\nClient : {:x?}\nServer : {:x?}",
             client_ctx.get_shared_key(),
             server_ctx.get_shared_key());

    println!("Full Opaque Key exchange protocol duration : {} ms", now.elapsed().as_millis());
}