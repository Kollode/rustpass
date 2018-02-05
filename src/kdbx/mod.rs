use std::fs::File;
use std::io::{Read, Error};
use std::convert::From;
use std::str;

use byteorder::{ByteOrder, LittleEndian};
use crypto::aes::ecb_encryptor;
use crypto::aes::KeySize;
use crypto::blockmodes::NoPadding;
use crypto::buffer::{RefReadBuffer, RefWriteBuffer};
use crypto::digest::Digest;
use crypto::sha2::Sha256;

pub enum HeaderTypes {
    End = 0,
    Comment = 1,
    CipherId = 2,
    Compression = 3,
    MasterSeed = 4,
    TransformSeed = 5,
    TransformRounds = 6,
    EncryptionIv = 7,
    ProtectedStreamKey = 8,
    StreamStartBytes = 9,
    InnerRandomStreamId = 10,
}

impl From<u8> for HeaderTypes {
    fn from(item: u8) -> Self {
        match item {
            0 => HeaderTypes::End,
            1 => HeaderTypes::Comment,
            2 => HeaderTypes::CipherId,
            3 => HeaderTypes::Compression,
            4 => HeaderTypes::MasterSeed,
            5 => HeaderTypes::TransformSeed,
            6 => HeaderTypes::TransformRounds,
            7 => HeaderTypes::EncryptionIv,
            8 => HeaderTypes::ProtectedStreamKey,
            9 => HeaderTypes::StreamStartBytes,
            10 => HeaderTypes::InnerRandomStreamId,
            _ => panic!("Type '{}' is unknown"),
        }
    }
}

#[derive(Debug)]
pub struct Header {
    file_signature_1: Option<Vec<u8>>,
    file_signature_2: Option<Vec<u8>>,
    file_version_minor: Option<u8>,
    file_version_major: Option<u8>,

    comment: Option<Vec<u8>>,
    cipher_id: Option<Vec<u8>>,
    compression: Option<Vec<u8>>,
    master_seed: Option<Vec<u8>>,
    transform_seed: Option<Vec<u8>>,
    transform_rounds: Option<u64>,
    encryption_iv: Option<Vec<u8>>,
    protected_stream_key: Option<Vec<u8>>,
    stream_start_bytes: Option<Vec<u8>>,
    inner_random_stream_id: Option<Vec<u8>>,
}

impl Header {
    fn new() -> Self {
        Header {
            file_signature_1: None,
            file_signature_2: None,
            file_version_minor: None,
            file_version_major: None,

            comment: None,
            cipher_id: None,
            compression: None,
            master_seed: None,
            transform_seed: None,
            transform_rounds: None,
            encryption_iv: None,
            protected_stream_key: None,
            stream_start_bytes: None,
            inner_random_stream_id: None,
        }
    }

    pub fn transformed_key(&self, composite_key: [u8; 32]) -> [u8; 32] {
        println!("transformed_key: generated based on: {:?}, {:?}, {:?}", self.transform_seed, self.transform_rounds, composite_key);

        let mut transformed_key = composite_key;
/*         let mut transform_seed = Some(Vec::new());
        transform_seed.clone_from(self.transform_seed);
        
        for _ in 0..self.transform_rounds.unwrap() {
            
             println!("transformed_key before crypt: {:?}", transformed_key);

            let mut key_buffer = [0u8; 32];
            let mut write_buffer = RefWriteBuffer::new(&mut key_buffer);

            let mut encryptor = ecb_encryptor(KeySize::KeySize256, transform_seed.unwrap().as_slice(), NoPadding);
            let mut read_buffer = RefReadBuffer::new(&transformed_key);
            encryptor.encrypt(&mut read_buffer, &mut write_buffer, true);

           // transformed_key = key_buffer.to_vec();
        }
 */
        println!("transformed_key: {:?}", transformed_key);

        return transformed_key;
    }
}

#[derive(Debug)]
pub enum DatabaseError {
    CantOpenFile(Error),
    CantReadFile(Error)
}

#[derive(Debug)]
pub struct Database {
    header: Header,
    payload: Vec<u8>
}

impl Database {

    pub fn create_from_path(path: &str, password: &str) -> Result<Self, DatabaseError> {
        match File::open(path) {
            Err(why) => Err(DatabaseError::CantOpenFile(why)),
            Ok(file) =>  Database::create_from_file(file, password),
        }
    }

    pub fn create_from_file(mut file: File, password: &str) -> Result<Self, DatabaseError> {
        let mut data = Vec::new();
        if let Err(error) = file.read_to_end(&mut data) {
            return Err(DatabaseError::CantReadFile(error));
        }

        let mut position: usize = 0;
        let header = Database::get_header(&mut position, &data)?;
        let payload = Database::get_payload(&data[position..], &header, password)?;

        Ok(Database {
            header,
            payload
        })
    }

    fn get_header(position: &mut usize, data: &[u8]) -> Result<Header, DatabaseError> {
        println!("==> Position start: {}", position);

        let mut header = Header::new();

        header.file_signature_1 = Some(data[0..4].to_vec());
        header.file_signature_2 = Some(data[4..8].to_vec());
        header.file_version_minor = Some(LittleEndian::read_u16(&data[8..10]) as u8);
        header.file_version_major = Some(LittleEndian::read_u16(&data[10..12]) as u8);

        *position = 12 as usize; //After file signature 1&2 and version
        println!("==> Position before header fields: {}", position);

        loop {
            let field_length: usize =
                LittleEndian::read_u16(&data[*position + 1..*position + 3]) as usize;
            let field_value = data[*position + 3..*position + 3 + field_length].to_vec();

            match HeaderTypes::from(data[*position]) {
                HeaderTypes::End => break,
                HeaderTypes::Comment => header.comment = Some(field_value),
                HeaderTypes::CipherId => header.cipher_id = Some(field_value),
                HeaderTypes::Compression => header.compression = Some(field_value),
                HeaderTypes::MasterSeed => header.master_seed = Some(field_value),
                HeaderTypes::TransformSeed => header.transform_seed = Some(field_value),
                HeaderTypes::TransformRounds => header.transform_rounds = Some(LittleEndian::read_u64(&field_value[..]) as u64),
                HeaderTypes::EncryptionIv => header.encryption_iv = Some(field_value),
                HeaderTypes::ProtectedStreamKey => header.protected_stream_key = Some(field_value),
                HeaderTypes::StreamStartBytes => header.stream_start_bytes = Some(field_value),
                HeaderTypes::InnerRandomStreamId => header.inner_random_stream_id = Some(field_value)
            }

            *position += 3 + field_length;
        };

        println!("==> Position end: {}", position);

        Ok(header)
    }

    fn get_payload(encrypted_payload: &[u8], header: &Header, password: &str) -> Result<Vec<u8>, DatabaseError> {
        println!("==> Start handling payload");

        let mut composite_key = [0u8; 32];

        let mut hasher = Sha256::new();
        hasher.input(password.as_bytes());
        hasher.result(&mut composite_key);

        let transformed_key = header.transformed_key(composite_key);

        Ok(vec![8])
    }
}
