use std::io;
use std::io::Write;
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
    println!("\nEnter the public key (n, g): ");
    print!("Enter n: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let n = base64_to_integer(input.as_str());
    print!("Enter e: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let e = base64_to_integer(input.as_str());
    let pk = (n.clone(), e);
    let mut randoms: Vec<Integer> = Vec::new();
    print!("\nHow many messages? ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let number = input.trim().parse().unwrap();
    for i in 0..number {
        print!("\nEnter x{i}: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .unwrap();
        randoms.push(base64_to_integer(input.as_str()));
    }
    print!("\nEnter b: ");
    io::stdout().flush().unwrap();
    let mut input = String::new();
    io::stdin()
        .read_line(&mut input)
        .unwrap();
    let b = input.trim().parse().unwrap();
    let mut rand = rand::RandState::new();
    let k = n.random_below(&mut rand);
    let v = base64::encode(encrypt_and_blind(&randoms, &pk, b, &k).to_string());
    println!("\nv: {v}");
    let mut ciphertexts: Vec<Integer> = Vec::new();
    for i in 0..number {
        print!("\nEnter ciphertext {i}: ");
        io::stdout().flush().unwrap();
        let mut input = String::new();
        io::stdin()
            .read_line(&mut input)
            .unwrap();
        ciphertexts.push(base64_to_integer(input.as_str()));
    }
    let output_plaintext = decrypt_message(&ciphertexts, &k, b);
    let output_plaintext = format!("{:X}", &output_plaintext);
    println!("\nChosen message: {}", String::from_utf8(hex::decode(output_plaintext).unwrap()).unwrap());
}
