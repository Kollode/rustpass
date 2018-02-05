extern crate byteorder;
extern crate clap;
extern crate crypto;
extern crate rpassword;

use clap::{App, Arg};

mod kdbx;
use kdbx::{ Database, DatabaseError };

/// Explains the kdbx format: https://gist.github.com/lgg/e6ccc6e212d18dd2ecd8a8c116fb1e45
fn main() {
    let matches = App::new("RustPass CLI")
        .version("1.0.0")
        .author("Kollode <patrick.kollodzik@gmail.com>")
        .about("Parse kdbx file and display the file header")
        .usage("rustpass -f ./passwords.kdbx")
        .arg(
            Arg::with_name("file")
                .short("f")
                .long("file")
                .value_name("FILE")
                .help("Path to kdbx file")
                .required(true)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("password")
                .short("p")
                .long("password")
                .help("Password to open payload")
                .required(false)
                .takes_value(true),
        )
        .arg(
            Arg::with_name("verbose")
                .short("v")
                .long("verbose")
                .multiple(true)
                .help("Sets the level of verbosity"),
        )
        .get_matches();

    let path_to_kdbx_file = matches.value_of("file").unwrap();
    let password: String;

    if matches.value_of("password").is_some() {
        password = String::from(matches.value_of("password").unwrap());
    }else {
        password = rpassword::prompt_password_stdout("Password: ").unwrap();
    }

    if matches.is_present("verbose") {
        println!("Open KDBX file at path: {}", path_to_kdbx_file);
        println!("Use password word: {}", password);
    }

    match Database::create_from_path(path_to_kdbx_file, &password) {
        Ok(db) => println!(" ==> KDBX Database: {:?}", db),
        Err(DatabaseError::CantOpenFile(error)) => println!(" ==> Could not open database: {:?}", error),
        Err(DatabaseError::CantReadFile(error)) => println!(" ==> Could not read database: {:?}", error)
    }
}
