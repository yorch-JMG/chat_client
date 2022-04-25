use pyo3::{types::PyModule, PyResult, Python};
use reqwest::Error;
use std::io::{self, ErrorKind, Read, Write};
use std::net::TcpStream;
use std::str;
use std::sync::mpsc::{self, TryRecvError};
use std::thread;
use std::time::Duration;

const LOCAL: &str = "127.0.0.1:6000";
const MSG_SIZE: usize = 64;

fn encrypt_message(message: &String) -> PyResult<String> {
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let encryption = PyModule::from_code(
            py,
            r#"
def vigenere(text: str, key: str, encrypt=True):
    result = ''
    for i in range(len(text)):
        letter_n = ord(text[i])
        key_n = ord(key[i % len(key)])

        if encrypt:
            value = (letter_n + key_n) % 1114112
        else:
            value = (letter_n - key_n) % 1114112

        result += chr(value)
    return result

def vigenere_encrypt(text: str, key: str):
    return vigenere(text=text, key=key, encrypt=True)
            "#,
            "vigenere.py",
            "vigenere",
        )?;
        let encrypted_message: String = encryption
            .getattr("vigenere_encrypt")?
            .call1((message, "hola".to_string()))?
            .extract()?;
        Ok(encrypted_message)
    })
}

fn decrypt_message(message: &String) -> PyResult<String> {
    pyo3::prepare_freethreaded_python();
    Python::with_gil(|py| {
        let decryption = PyModule::from_code(
            py,
            r#"
def vigenere(text: str, key: str, encrypt=True):
    result = ''
    for i in range(len(text)):
        letter_n = ord(text[i])
        key_n = ord(key[i % len(key)])

        if encrypt:
            value = (letter_n + key_n) % 1114112
        else:
            value = (letter_n - key_n) % 1114112

        result += chr(value)
    return result

def vigenere_decrypt(text: str, key: str):
    return vigenere(text=text, key=key, encrypt=False)
            "#,
            "vigenere.py",
            "vigenere",
        )?;
        let decrypted_message: String = decryption
            .getattr("vigenere_decrypt")?
            .call1((message, "hola"))?
            .extract()?;
        Ok(decrypted_message)
    })
}

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut client = TcpStream::connect(LOCAL).expect("Stream failed to connect");
    client
        .set_nonblocking(true)
        .expect("failed to initiate non-blocking");
    let (tx, rx) = mpsc::channel::<String>();

    thread::spawn(move || loop {
        let mut buff = vec![0; MSG_SIZE];
        match client.read_exact(&mut buff) {
            Ok(_) => {
                let bytes = buff.into_iter().take_while(|&x| x != 0).collect::<Vec<_>>();
                let _msg = match str::from_utf8(&bytes) {
                    Ok(v) => {
                        let user = v[..15].to_string();
                        let msg = v[15..].to_string();
                        let decrypted_msg = decrypt_message(&msg.to_string()).unwrap();
                        println!("{} :{:?}", &user, decrypted_msg);
                        println!();
                    }
                    Err(e) => panic!("Invalid UTF-8 sequence: {}", e),
                };
            }
            Err(ref err) if err.kind() == ErrorKind::WouldBlock => (),
            Err(_) => {
                println!("connection with server was severed");
                break;
            }
        }

        match rx.try_recv() {
            Ok(msg) => {
                let mut buff = msg.clone().into_bytes();
                buff.resize(MSG_SIZE, 0);
                client.write_all(&buff).expect("writing to socket failed");
                println!("You sent {:?}", msg);
                println!();
            }
            Err(TryRecvError::Empty) => (),
            Err(TryRecvError::Disconnected) => break,
        }

        thread::sleep(Duration::from_millis(100));
    });

    println!("Write a message:");
    loop {
        let mut buff = String::new();
        io::stdin()
            .read_line(&mut buff)
            .expect("reading from stdin failed");
        let msg = buff.trim().to_string();
        let encrypted_msg = encrypt_message(&msg).unwrap();
        if msg == ":quit" || tx.send(encrypted_msg).is_err() {
            break;
        }
    }
    println!("bye bye!");
    Ok(())
}
