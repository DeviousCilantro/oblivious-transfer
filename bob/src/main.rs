use std::io;
use std::net::TcpListener;
use std::io::{Read,Write};
use rug::{Integer, rand};

fn encrypt_and_blind(randoms: &Vec<Integer>, pk: &(Integer, Integer), b: u32, k: &Integer) -> Integer {
    let (n, e) = pk;
    if b < u32::try_from(randoms.len()).unwrap() {
        (randoms[b as usize].clone() % n.clone() + k.clone().secure_pow_mod(e, n)) % n.clone()
    } else {
        Integer::from(0)
    }
}

fn decrypt_message(ciphertexts: &Vec<Integer>, k: &Integer, b: u32) -> Integer {
    if b < u32::try_from(ciphertexts.len()).unwrap() {
        ciphertexts[b as usize].clone() - k
    } else {
        Integer::from(0)
    }
}

fn base64_to_integer(input: &str) -> Integer {
    let input = String::from_utf8(base64::decode(input.trim()).unwrap()).unwrap();
    let input = input.as_str();
    Integer::from_str_radix(input, 10).unwrap()
}

fn main() {
    let receiver_listener = TcpListener::bind("127.0.0.1:6969").expect("Failed and bind with the sender");
    println!("Listening on localhost:6969...");
    let mut stream = receiver_listener.accept().unwrap().0;
    let mut buf = [0; 4096];
    let mut received_bytes = Vec::new();
    let bytes_read = stream.read(&mut buf).unwrap();
    received_bytes.extend_from_slice(&buf[..bytes_read]);
    let zero_pos = received_bytes.iter().position(|&b| b == 0).unwrap_or(received_bytes.len());
    let received_string = String::from_utf8_lossy(&received_bytes[..zero_pos]).to_string();
    let received_vec: Vec<&str> = received_string.split(' ').collect();
    let n = base64_to_integer(received_vec[0]);
    let e = base64_to_integer(received_vec[1]);
    let pk = (n.clone(), e);
    let mut randoms: Vec<Integer> = Vec::new();
    let number = received_vec.len() - 2;
    for i in 0..number {
        randoms.push(base64_to_integer(received_vec[i + 2]));
    }
    print!("\nEnter the index of the message to be retrieved: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let b = input.trim().parse().unwrap();
    let mut rand = rand::RandState::new();
    let k = n.random_below(&mut rand);
    let v = base64::encode(encrypt_and_blind(&randoms, &pk, b, &k).to_string());
    let mut stream = receiver_listener.accept().unwrap().0;
    println!("\nSending v to Alice...");
    stream.write_all(v.as_bytes()).expect("failed to write");
    stream.flush().unwrap();
    drop(stream);
    let mut stream = receiver_listener.accept().unwrap().0;
    let mut buf = [0; 4096];
    let bytes_read = stream.read(&mut buf).unwrap();
    received_bytes = Vec::new();
    received_bytes.extend_from_slice(&buf[..bytes_read]);
    let zero_pos = received_bytes.iter().position(|&b| b == 0).unwrap_or(received_bytes.len());
    let received_string = String::from_utf8_lossy(&received_bytes[..zero_pos]).to_string();
    let received_vec: Vec<&str> = received_string.split(' ').collect();
    let mut ciphertexts: Vec<Integer> = Vec::new();
    for element in received_vec {
        ciphertexts.push(base64_to_integer(element));
    }
    let output_plaintext = decrypt_message(&ciphertexts, &k, b);
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("\nRetrieved message: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
}
