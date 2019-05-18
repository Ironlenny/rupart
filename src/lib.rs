// This is an implementation of
// [Parity Volume Set Specification 2.0](
// http://parchive.sourceforge.net/docs/specifications/parity-volume-spec/article-spec.html)

#![allow(dead_code, unused_must_use)]
use crc32fast::Hasher;
use failure::ResultExt;
use itertools::Itertools;
use md5::{Digest, Md5};
use rayon::prelude::*;
use rayon::{join, spawn};
use std::cmp::Ordering;
use std::collections::{BinaryHeap, HashMap};
use std::fs::metadata;
use std::fs::File;
use std::io::prelude::*;
use std::mem::drop;
use std::path::PathBuf;
use std::sync::mpsc::{channel, Receiver, Sender};
use std::sync::{Arc, RwLock, RwLockWriteGuard};

// First 16 KiB of a file
static FIRST_16K: usize = 16384;

// File creation pipeline

pub struct CreatorPipeline {
    magic: Arc<[u8; 8]>,
    rec_set_id: Arc<RwLock<[u8; 16]>>,
    file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
}

// Creation pipeline methods
impl CreatorPipeline {
    pub fn new() -> Self {
        CreatorPipeline {
            magic: Arc::new(*b"PAR2\0PKT"),
            rec_set_id: Arc::new(RwLock::new([0; 16])),
            file_ids: Arc::new(RwLock::new(Vec::new())),
        }
    }

    pub fn run<T>(
        &self,
        files: Vec<PathBuf>,
        block_size: usize,
        parity: usize,
    ) -> Receiver<Message> {
        let (tx_writes, rx_writes): (Sender<Message>, Receiver<Message>) = channel();
        let (tx_input, rx_input): (Sender<Message>, Receiver<Message>) = channel();
        let (tx_body, rx_body): (Sender<Message>, Receiver<Message>) = channel();
        let (tx_file_descript, rx_file_descript): (Sender<Message>, Receiver<Message>) = channel();
        let (tx_recovery, rx_recovery): (Sender<Message>, Receiver<Message>) = channel();

        // spawn(move || create_file_id(tx_main, tx_input, tx_file_descript, files));

        rx_writes
    }
}

// Type trait for sending body types to header channel
trait Type {
    fn is_type(&self) -> Box<&[u8; 16]>;
}

// Hashs are 16 bytes (&[u8; 16])

// Header for all packets

pub struct Header<T> {
    magic: Arc<[u8; 8]>,               // ASCII string
    length: u64,        // Packet length starting at first byte of rec_set_id. 8 bytes
    pkt_hash: [u8; 16], // 16 bytes
    rec_set_id: Arc<Option<[u8; 16]>>, // 16 bytes
    pkt_type: [u8; 16], // ASCII string
    body: T,
}

// Main packet body

pub struct Main {
    block_size: u64,
    num_files: u32, // 4 bytes
    file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
    rec_file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
}

impl Type for Main {
    fn is_type(&self) -> Box<&[u8; 16]> {
        let string: Box<&[u8; 16]> = Box::new(b"PAR 2.0\0Main\0\0\0\0");
        string
    }
}

// File Description packet body

pub struct FileDescription {
    file_id: Arc<[u8; 16]>,
    file_hash: [u8; 16],
    hash_16k: [u8; 16], // Hash of first 16k of file
    length: u64,        // Length of file
    name: Vec<u8>,      // ASCII string
}

impl Type for FileDescription {
    fn is_type(&self) -> Box<&[u8; 16]> {
        let string: Box<&[u8; 16]> = Box::new(b"PAR 2.0\0FileDesc");
        string
    }
}

// Input File Block Checksum packet body

pub struct Input {
    file_id: Arc<[u8; 16]>,
    block_checksums: Vec<([u8; 16], u32)>, // Hash and CRC32 tuple
}

impl Type for Input {
    fn is_type(&self) -> Box<&[u8; 16]> {
        let string: Box<&[u8; 16]> = Box::new(b"par 2.0\0ifsc\0\0\0\0");
        string
    }
}

// Recovery Block packet body

pub struct Recovery {
    exponent: u32,
    blocks: Vec<u32>,
}

impl Type for Recovery {
    fn is_type(&self) -> Box<&[u8; 16]> {
        let string: Box<&[u8; 16]> = Box::new(b"PAR 2.0\0RecvSlic");
        string
    }
}

// Creator packet body

pub struct Creator {
    id: [u8; 16], // ASCII string
}

impl Type for Creator {
    fn is_type(&self) -> Box<&[u8; 16]> {
        let string: Box<&[u8; 16]> = Box::new(b"PAR 2.0\0Creator\0");
        string
    }
}

// Block Convenience struct. The spec references slices. Slices and blocks are
// the same thing. A block is an array of 16-bit values
// #[derive(Eq)]
pub struct Block {
    file_id: Arc<[u8; 16]>,
    index: usize,
    data: Arc<Vec<u8>>,
    block_size: usize,
    num_blocks: usize,
    length: u64,
}

// impl PartialOrd for Block {
//     fn partial_cmp(&self, other: &Block) -> Option<Ordering> {
//         self.index.partial_cmp(&other.index)
//     }
// }

// impl PartialEq for Block {
//     fn eq(&self, other: &Block) -> bool {
//         self.index == other.index
//     }
// }

// impl Ord for Block {
//     fn cmp(&self, other: &Block) -> Ordering {
//         self.index.cmp(&other.index).reverse()
//     }
// }

// The `Buffer` struct sorts and stores blocks for when they are needed
// struct Buffer {
//     heap: BinaryHeap<Arc<Block>>,
//     count: usize,
//     num_blocks: usize,
// }

// impl Buffer {
//     fn new() -> Self {
//         Buffer {
//             heap: BinaryHeap::new(),
//             count: 0,
//             num_blocks: 0,
//         }
//     }

//     fn is_done(&self) -> bool {
//         if self.num_blocks == self.count {
//             return true;
//         }

//         false
//     }

//     fn process(&mut self, block: Arc<Block>) -> Option<Arc<Block>> {
//         let mut result = None;

//         if self.num_blocks == 0 {
//             self.num_blocks = block.num_blocks;
//         }

//         //Check for first blocks
//         if block.index == 0 {
//             self.count = self.count + 1;
//             result = Some(block);
//         }
//         // Check if current block is the one we need
//         else if self.count > 0 && block.index == self.count {
//             self.count = self.count + 1;
//             result = Some(block);
//         }
//         // Check if root is the one we need
//         else if !self.heap.is_empty() {
//             if {
//                 let root = self.heap.peek().unwrap();
//                 root.index
//             } == self.count
//             {
//                 result = Some(self.heap.pop().unwrap());
//             }
//         }
//         // We can't use this block yet
//         else {
//             self.heap.push(block);
//         }

//         result
//     }
// }

// Body enum indicates the type of packet body, and contains a body struct
pub enum Body {
    Main(Main),
    FileDescription(FileDescription),
    Input(Input),
    Recovery(Recovery),
    Creator(Creator),
}

// Signal which channel to close
pub enum Close {
    FileID,
    Block,
}

// Message enum indicates the type of message, and contains a message body
pub enum Message {
    Packet(Header<Body>),                                          // writes Packet
    Main(Arc<[u8; 16]>),                                           // main file_id
    Input(Block),                                                  // input (file_id, file, length)
    FileDescription((Vec<u8>, u64, Box<[u8; 16]>, Arc<[u8; 16]>)), // file_descript (name, length, hash_16k, file_id)
    Block(Arc<Block>),                                             // recovery Block
    Body(Body),                                                    // packet Body
    Close(Close),                                                  // Close a channel
}

// Helper function to convert Vec's to byte arrays
fn convert_to_byte_array(vec: Vec<u8>) -> [u8; 16] {
    let mut temp: [u8; 16] = [0; 16];

    for i in 0..16 {
        temp[i] = vec[i];
    }

    temp
}

// `get_input()` makes `Blocks` from a file.
fn get_input(
    tx_router: Sender<Message>,
    files: Vec<PathBuf>,
    block_size: usize,
    mut file_ids: RwLockWriteGuard<Vec<[u8; 16]>>,
) {
    // `MessageBlock` is an iterator that makes `Blocks`
    struct MessageBlock {
        path: PathBuf,
        file_id: Option<Arc<[u8; 16]>>,
        reader: File,
        block_size: usize,
        num_blocks: usize,
        length: u64,
        blocks: Vec<Arc<Vec<u8>>>,
    }

    impl MessageBlock {
        fn new(path: PathBuf, block_size: usize) -> Self {
            let length = {
                let metadata = metadata(&path).unwrap();
                metadata.len()
            };

            MessageBlock {
                path: path.clone(),
                file_id: None,
                reader: { File::open(&path).unwrap() },
                block_size: block_size,
                num_blocks: { length as usize / block_size },
                length: length,
                blocks: Vec::new(),
            }
        }
    }

    impl Iterator for MessageBlock {
        type Item = Block;

        fn next(&mut self) -> Option<Block> {
            if self.file_id.is_none() {
                let mut reader = &mut self.reader;
                while self.blocks.len() <= FIRST_16K % self.block_size + 1 {
                    match reader
                        .bytes()
                        .chunks(self.block_size)
                        .into_iter()
                        .enumerate()
                        .next()
                    {
                        Some(next) => {
                            let (i, chunk) = next;
                            let block = Arc::new(chunk.map(|x| x.unwrap()).collect());
                            self.blocks.push(block);
                        }
                        None => panic!("Empty file"),
                    }
                }

                let file_id = create_file_id(&self.blocks, &self.path, self.length);
                self.file_id = Some(file_id);
            }

            if !self.blocks.is_empty() {
                let (i, block) = self.blocks.iter().enumerate().next().unwrap();
                let file_id = {
                    if let Some(id) = self.file_id.clone() {
                        id
                    } else {
                        panic!()
                    }
                };

                let message_block = Block {
                    file_id: Arc::clone(&file_id),
                    index: i,
                    data: block.to_owned(),
                    block_size: self.block_size,
                    num_blocks: self.num_blocks,
                    length: self.length,
                };

                return Some(message_block);
            }

            let reader = &mut self.reader;
            let result = match reader
                .bytes()
                .chunks(self.block_size)
                .into_iter()
                .enumerate()
                .next()
            {
                Some(next) => {
                    let (i, chunk) = next;
                    let block = Arc::new(chunk.map(|x| x.unwrap()).collect());

                    let message_block = Block {
                        file_id: {
                            if let Some(id) = self.file_id.clone() {
                                id
                            } else {
                                panic!()
                            }
                        },
                        index: i,
                        data: block,
                        block_size: self.block_size,
                        num_blocks: self.num_blocks,
                        length: self.length,
                    };

                    Some(message_block)
                }
                None => None,
            };

            result
        }
    }

    let mut readers = Vec::new();

    for file in files {
        readers.push({ MessageBlock::new(file, block_size) });
    }

    // Send first blocks so file ids can be created
    for reader in &mut readers {
        let block = reader.next().unwrap();
        file_ids.push(*block.file_id);
        let message = Message::Block(Arc::new(block));
        tx_router.send(message).unwrap();
    }

    // Close file id channel
    tx_router.send(Message::Close(Close::FileID));

    // Send the rest of them
    // readers.iter().for_each(|reader| {
    //     reader.for_each(|message| {
    //         let message = Message::Block(Arc::new(message));
    //         tx_router.send(message);
    //     });
    // });

    for reader in readers {
        for block in reader {
            let message = Message::Block(Arc::new(block));
            tx_router.send(message).unwrap();
        }
    }

    // Close block channels
    tx_router.send(Message::Close(Close::Block));

    file_ids.par_sort_unstable();
}

// First Stage: Create file ids and partial bodies for FileDescription. Send
// file ids, partial bodies and file readers to the correct channels.
fn create_file_id(blocks: &Vec<Arc<Vec<u8>>>, file: &PathBuf, length: u64) -> Arc<[u8; 16]> {
    // Get filename from path
    let name = file
        .file_stem()
        .unwrap()
        .to_string_lossy()
        .into_owned()
        .into_bytes();

    // Hash first 16k of the file
    let hash_16k = {
        let mut hasher_16k = Md5::new();
        let buffer: Vec<u8> = blocks
            .iter()
            .map(|block| block.iter())
            .flatten()
            .take(FIRST_16K)
            .map(|byte| *byte)
            .collect();
        hasher_16k.input(buffer);
        let result = hasher_16k.result();
        let hash_16k = result.as_slice().to_owned();
        Box::new(convert_to_byte_array(hash_16k))
    };

    // Generate File ID
    let file_id = {
        let mut hasher_file_id = Md5::new();
        hasher_file_id.input(&*hash_16k);
        hasher_file_id.input(&length.to_le_bytes());
        hasher_file_id.input(&name);
        let file_id = hasher_file_id.result().to_vec();
        let file_id = convert_to_byte_array(file_id);

        Arc::new(file_id)
    };

    file_id
}

// Second Stage
fn create_main(
    tx_router: Sender<Message>,
    mut rec_set_id: RwLockWriteGuard<[u8; 16]>,
    file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
    block_size: usize,
) {
    let id_lock = file_ids.read().unwrap();
    let mut hasher = Md5::new();

    let body = Main {
        block_size: block_size as u64,
        num_files: {
            let num_files = &*id_lock;
            let num_files = num_files.len() as u32;
            num_files
        },
        file_ids: Arc::clone(&file_ids),
        rec_file_ids: Arc::clone(&file_ids),
    };

    // Create rec_set_id
    hasher.input(&body.block_size.to_le_bytes());
    hasher.input(&body.num_files.to_le_bytes());
    // file_ids and rec_files_ids are the same
    for _ in 0..1 {
        for bytes in &*id_lock {
            hasher.input(bytes);
        }
    }

    // Set rec_set_id
    *rec_set_id = convert_to_byte_array(hasher.result().to_vec());
    tx_router.send(Message::Body(Body::Main(body))).unwrap();
}

// Third Stage: Take file ids, file readers, and block_size; and create an input body
// containing file id and block checksums. Iterate through the file reader calculating
// block hashs. Put hashs in a Vec. Send complete body to create_packet(). Bock size is bytes
fn create_input_body(rx_input: Receiver<Message>, tx_router: Sender<Message>) {
    for received in rx_input {
        let file_hash = Md5::new();
        let (tx_block, rx_block) = channel();
        let block = match received {
            Message::Input(input) => input,
            _ => panic!(),
        };

        // Check if block needs padding
        // let temp_vec = (*block.data).clone(); temp_vec.resize(block.block_size, 0)

        let body = Body::Input(Input {
            file_id: Arc::clone(&block.file_id),
            block_checksums: {
                // Pre-allocate block_checksums vector to eliminate the need for sorting
                let mut block_checksums: Vec<([u8; 16], u32)> =
                    vec![([0; 16], 0); block.num_blocks];

                let tx = tx_block.clone();

                spawn(move || {
                    let mut md5_sum = Vec::new();
                    let mut crc_sum = 0;

                    join(
                        || {
                            let mut hasher_md5 = Md5::new();
                            hasher_md5.input(&*block.data);
                            md5_sum = hasher_md5.result().to_vec();
                        },
                        || {
                            let mut hasher_crc32 = Hasher::new();
                            hasher_crc32.update(&*block.data);
                            crc_sum = hasher_crc32.finalize();
                        },
                    );

                    let result = (block.index, md5_sum, crc_sum);
                    tx.send(result).unwrap();
                });

                // Close block channel
                drop(tx_block);

                for block in rx_block {
                    let (index, md5, crc) = block;
                    block_checksums[index] = (convert_to_byte_array(md5), crc);
                }

                block_checksums
            },
        });

        tx_router.send(Message::Body(body)).unwrap();
    }
}

// Fourth Stage
// fn create_rec_body(
//     rx_recovery: Receiver<Message>,
//     tx_body: Receiver<Message>,
//     parity: usize,
//     file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
// ) {
//     let file_ids = file_ids.read().unwrap();
//     //  Assign constant to input block = power of two with order 65535
//     let mut constant = 2;
//     let constant_incr = || loop {
//         constant = constant + 1;

//         if constant % 3 != 0 && constant % 5 != 0 && constant % 17 != 0 && constant % 257 != 0 {
//             break;
//         }
//     };

//     //  Assign exponent to recovery block = start 0
//     let exponent = 0;
//     //  recovery = (inputA * constantA ^ exponent) + (inputB * constantB ^ exponent)

//     for received in rx_recovery {
//         let received = match received {
//             Message::Block(block) => block,
//             _ => panic!(),
//         };
//     }
// }

// Fifth Stage
fn create_file_description(
    rx_fd: Receiver<Message>,
    tx_router: Sender<Message>,
    file_ids: Arc<RwLock<Vec<[u8; 16]>>>,
) {
    let file_ids = file_ids.read().unwrap();
    let mut senders: HashMap<&[u8; 16], (Sender<Arc<Block>>, usize)> = HashMap::new();
    let mut recvs = HashMap::new();

    for id in &*file_ids {
        let (tx, rx) = channel();
        senders.insert(id, (tx, 0));
        recvs.insert(id, rx);
    }

    for received in rx_fd {
        match received {
            Message::FileDescription(partial) => {
                let (name, length, hash_16k, file_id) = partial;
                let tx_router = tx_router.clone();
                let rx = recvs.remove(&*file_id).unwrap();
                spawn(move || {
                    let body = Body::FileDescription(FileDescription {
                        file_id: Arc::clone(&file_id),
                        file_hash: {
                            let mut hasher = Md5::new();

                            for block in rx {
                                hasher.input(&*block.data);
                            }

                            let result = hasher.result().to_vec();
                            convert_to_byte_array(result)
                        },
                        hash_16k: *hash_16k,
                        length: length,
                        name: name,
                    });

                    tx_router.send(Message::Body(body)).unwrap();
                });
            }
            Message::Block(block) => {
                let id = &*block.file_id;
                let sender = senders.get_mut(id).unwrap();
                let tx = &sender.0;
                let mut count = sender.1;
                tx.send(Arc::clone(&block)).unwrap();
                count = count + 1;

                if count >= block.num_blocks {
                    drop(tx);
                }
            }
            _ => panic!("No valid message"),
        }
    }
}

// Sixth Stage
fn create_creator(tx_router: Sender<Message>) {
    let body = Body::Creator(Creator {
        id: b"Rust\0Parity\0Tool".clone(),
    });

    tx_router.send(Message::Body(body)).unwrap();
}

// // fn create_packet(pipeline: CreatorPipeline, pkt_type: Type, body: T,) -> Header<T> {
//     let header = Header {
//         magic: &self.magic,
//         rec_set_id: &self.rec_set_id,
//         length: { 64 + size_of(body) }, // 64 is the size of header in bytes
//         pkt_hash:
//     }
// }

#[cfg(test)]
mod test {
    use super::*;
    use crc32fast::Hasher;
    use hex_literal::hex;
    use lazy_static::lazy_static;
    use md5::{Digest, Md5};
    use rayon::join;
    use std::fs::File;
    use std::path::PathBuf;
    use typename::TypeName;

    static PATH: &str = "/home/jacob/projects/rupart/test_file";
    static NAME: &[u8; 9] = b"test_file";

    lazy_static! {
        static ref FILE_ID: [u8; 16] = hex!("7a9b4bacc05e6c2eb59f25c687f900c4");
    }

    lazy_static! {
        static ref HASH_16K: [u8; 16] = hex!("54e39774f15c24a19b8553e3a2408af1");
    }

    static LENGTH: u64 = 1048576;
    static BLOCK_SIZE: usize = 65536;

    lazy_static! {
        static ref NUM_BLOCKS: usize = LENGTH as usize / BLOCK_SIZE;
    }

    lazy_static! {
        static ref BLOCKS: Vec<Arc<Vec<u8>>> = {
            let path = PathBuf::from(&PATH);
            let mut blocks = Vec::new();
            let reader = File::open(&path).unwrap();

            for chunk in reader.bytes().chunks(BLOCK_SIZE).into_iter() {
                let block = chunk.map(|x| x.unwrap()).collect();
                let block = Arc::new(block);
                blocks.push(block);
            }
            blocks
        };
    }

    #[test]
    fn pipeline_creation() {
        CreatorPipeline::new();
    }

    #[test]
    fn creator_body_creation() {
        let (tx_router, rx_router) = channel();

        create_creator(tx_router);

        // Test router channel
        let result = match rx_router.recv().unwrap() {
            Message::Body(Body::Creator(creator)) => creator,
            _ => panic!("Received something other than a creator body"),
        };

        // Check that id hasn't changed
        assert_eq!(b"Rust\0Parity\0Tool", &result.id);
        // Check that type hasn't changed
        assert_eq!(b"PAR 2.0\0Creator\0", *result.is_type());
    }

    #[test]
    fn file_id_creation() {
        // Test setup
        let path = PathBuf::from(&PATH);
        // End setup

        // Test file id
        let file_id = create_file_id(&*BLOCKS, &path, LENGTH);
        assert_eq!(*file_id, *FILE_ID);
    }

    #[test]
    fn input_body_creation() {
        // Test setup
        let block_size = 65536;
        let num_blocks = 16;
        let path = PathBuf::from(&PATH);
        let (tx_router, rx_router) = channel();
        let (tx_input, rx_input) = channel();
        let mut hashs_md5 = Vec::new();
        let mut hashs_crc = Vec::new();

        for block in &*BLOCKS {
            join(
                || {
                    let hash = Md5::digest(&block.clone());
                    let hash = hash.as_slice().to_vec();
                    let hash = convert_to_byte_array(hash);
                    &hashs_md5.push(hash);
                },
                || {
                    let mut hasher = Hasher::new();
                    hasher.update(&block.clone());
                    &hashs_crc.push(hasher.finalize());
                },
            );
        }

        let mut hashs = hashs_md5.into_iter().zip(hashs_crc.into_iter());
        let input = Message::Input((Arc::new(FILE_ID.to_owned()), path, LENGTH));
        tx_input.send(input);
        drop(tx_input);
        create_input_body(rx_input, tx_router, block_size);
        // End test setup

        // Test output
        for received in rx_router {
            match &received {
                Message::Body(Body::Input(input)) => {
                    // Test body type
                    assert_eq!(
                        *input.is_type(),
                        b"par 2.0\0ifsc\0\0\0\0",
                        "Wrong body type"
                    );

                    // Test file_id
                    assert_eq!(
                        *input.file_id,
                        hex!("7a9b4bacc05e6c2eb59f25c687f900c4"),
                        "Wrong file id"
                    );

                    // Test hashs
                    let mut count = 0;
                    for hash in &input.block_checksums {
                        count = count + 1; // Count blocks
                        let (md5, crc) = hashs.next().unwrap();
                        assert_eq!(hash, &(md5, crc), "input hashes don't match");
                    }

                    // Should have 16 blocks
                    assert_eq!(count, 16);
                }
                Message::Block(block) => {
                    let block = block;
                    // Tests
                    // file id
                    assert_eq!(*block.file_id, *FILE_ID);
                    // data at index
                    assert!({
                        let mut result = false;
                        if *block.data == BLOCKS[block.index] {
                            result = true
                        }
                        result
                    });
                    // vec_length
                    assert_eq!(block.num_blocks, num_blocks);
                }
                _ => panic!("No valid message"),
            }
        }
    }

    #[test]
    fn file_description_body_creation() {
        // Test setup
        const FIRST_16K: usize = 16384;
        let (tx_fd, rx_fd) = channel();
        let (tx_router, rx_router) = channel();
        let path = PathBuf::from(&PATH);
        let file_ids = Arc::new(RwLock::new(vec![FILE_ID.to_owned()]));
        let mut reader = File::open(&path).unwrap();
        let mut buffer = [0; FIRST_16K];
        let reader = File::open(&path).unwrap();

        for (i, block) in BLOCKS.iter().enumerate() {
            if i == 0 {
                for (i, byte) in block.iter().enumerate() {
                    if i < FIRST_16K {
                        buffer[i] = *byte;
                    }
                }
            }

            let block = Arc::new(block.to_owned());

            let message_block = Arc::new(Block {
                file_id: Arc::new(FILE_ID.to_owned()),
                index: i.clone(),
                data: Arc::clone(&block),
                // vec_length: BLOCK_SIZE,
                num_blocks: *NUM_BLOCKS,
            });

            tx_fd.send(Message::Block(message_block));
        }

        let hasher = Md5::digest(&buffer);
        let hasher = Box::new(convert_to_byte_array(hasher.to_vec()));
        let partial = (
            PATH.as_bytes().to_vec(),
            LENGTH.to_owned(),
            hasher,
            Arc::new(FILE_ID.to_owned()),
        );
        tx_fd.send(Message::FileDescription(partial)).unwrap();
        drop(tx_fd);
        create_file_description(rx_fd, tx_router, file_ids);
        // End setup

        // Test received
        let received = rx_router.recv().unwrap();
        let body = match received {
            Message::Body(Body::FileDescription(body)) => body,
            _ => panic!("Got something other than a FileDescription body!"),
        };

        // Test file id
        assert_eq!(body.file_id[..], *FILE_ID, "Wrong file id");
        // Test hash
        assert_eq!(
            body.file_hash[..],
            hex!("7a27aa352924434d042415ab8fa477cf"),
            "Wrong file hash"
        );
        // Test hash_16k
        assert_eq!(body.hash_16k[..], *HASH_16K, "Wrong hash of first 16k");
        // Test length
        assert_eq!(body.length, LENGTH);
        // Test name
        assert_eq!(body.name, PATH.to_owned().as_bytes());
    }
}
