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

// File creation pipeline
#[derive(Debug)]
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
#[derive(Debug)]
pub struct Header<T> {
    magic: Arc<[u8; 8]>,               // ASCII string
    length: u64,        // Packet length starting at first byte of rec_set_id. 8 bytes
    pkt_hash: [u8; 16], // 16 bytes
    rec_set_id: Arc<Option<[u8; 16]>>, // 16 bytes
    pkt_type: [u8; 16], // ASCII string
    body: T,
}

// Main packet body
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug)]
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
#[derive(Debug, Eq)]
pub struct Block {
    file_id: Arc<[u8; 16]>,
    index: usize,
    data: Arc<Vec<u8>>,
    // vec_length: usize,
    num_blocks: usize,
}

impl PartialOrd for Block {
    fn partial_cmp(&self, other: &Block) -> Option<Ordering> {
        self.index.partial_cmp(&other.index)
    }
}

impl PartialEq for Block {
    fn eq(&self, other: &Block) -> bool {
        self.index == other.index
    }
}

impl Ord for Block {
    fn cmp(&self, other: &Block) -> Ordering {
        self.index.cmp(&other.index).reverse()
    }
}

// The `Buffer` struct sorts and stores blocks for when they are needed
struct Buffer {
    heap: BinaryHeap<Arc<Block>>,
    count: usize,
    num_blocks: usize,
}

impl Buffer {
    fn new() -> Self {
        Buffer {
            heap: BinaryHeap::new(),
            count: 0,
            num_blocks: 0,
        }
    }

    fn is_done(&self) -> bool {
        if self.num_blocks == self.count {
            return true;
        }

        false
    }

    fn process(&mut self, block: Arc<Block>) -> Option<Arc<Block>> {
        let mut result = None;

        if self.num_blocks == 0 {
            self.num_blocks = block.num_blocks;
        }

        //Check for first blocks
        if block.index == 0 {
            self.count = self.count + 1;
            result = Some(block);
        }
        // Check if current block is the one we need
        else if self.count > 0 && block.index == self.count {
            self.count = self.count + 1;
            result = Some(block);
        }
        // Check if root is the one we need
        else if !self.heap.is_empty() {
            if {
                let root = self.heap.peek().unwrap();
                root.index
            } == self.count
            {
                result = Some(self.heap.pop().unwrap());
            }
        }
        // We can't use this block yet
        else {
            self.heap.push(block);
        }

        result
    }
}

// Body enum indicates the type of packet body, and contains a body struct
#[derive(Debug)]
pub enum Body {
    Main(Main),
    FileDescription(FileDescription),
    Input(Input),
    Recovery(Recovery),
    Creator(Creator),
}

// Message enum indicates the type of message, and contains a message body
#[derive(Debug)]
pub enum Message {
    Writes(Header<Body>),                                          // writes Packet
    Main(Arc<[u8; 16]>),                                           // main file_id
    Input((Arc<[u8; 16]>, PathBuf, u64)),                          // input (file_id, file, length)
    FileDescription((Vec<u8>, u64, Box<[u8; 16]>, Arc<[u8; 16]>)), // file_descript (name, length, hash_16k, file_id)
    Block(Arc<Block>),                                             // recovery Block
    Body(Body),                                                    // packet Body
}

// Helper function to convert Vec's to byte arrays
fn convert_to_byte_array(vec: Vec<u8>) -> [u8; 16] {
    let mut temp: [u8; 16] = [0; 16];

    for i in 0..16 {
        temp[i] = vec[i];
    }

    temp
}

// First Stage: Create file ids and partial bodies for FileDescription. Send
// file ids, partial bodies and file readers to the correct channels.
fn create_file_id(
    tx_router: Sender<Message>,
    files: Vec<PathBuf>,
    mut file_ids: RwLockWriteGuard<Vec<[u8; 16]>>,
) {
    let (tx_id, rx_id): (Sender<[u8; 16]>, Receiver<[u8; 16]>) = channel();

    for file in files {
        let tx_id = tx_id.clone();
        let tx_router = tx_router.clone();
        let mut reader = File::open(&file)
            .with_context(|_| format!("Could not open file {}", file.display()))
            .unwrap();
        let mut buffer = [0; 16384];
        reader.read(&mut buffer).unwrap();

        // Spawn thread
        spawn(move || {
            // Get filename from path
            let name = file
                .file_stem()
                .unwrap()
                .to_string_lossy()
                .into_owned()
                .into_bytes();

            let length = {
                let metadata = metadata(&file).unwrap();
                metadata.len()
            };

            // Hash first 16k of the file
            let hash_16k = {
                let mut hasher_16k = Md5::new();
                for byte in buffer.iter() {
                    hasher_16k.input([byte.to_owned()]);
                }

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

            // Partial FileDescription (name, length, hash_16k)
            let partial_body = (name, length, hash_16k, Arc::clone(&file_id));

            // sender for channels
            tx_id.send(*file_id).unwrap();
            tx_router
                .send(Message::Input((Arc::clone(&file_id), file, length)))
                .unwrap();
            tx_router
                .send(Message::FileDescription(partial_body))
                .unwrap();
        });
    }
    drop(tx_id);

    // Add to pipeline
    for received in rx_id {
        file_ids.push(received);
    }

    file_ids.par_sort_unstable();
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
fn create_input_body(rx_input: Receiver<Message>, tx_router: Sender<Message>, block_size: usize) {
    for received in rx_input {
        let file_hash = Md5::new();
        let (tx_block, rx_block) = channel();
        let (file_id, file, length) = match received {
            Message::Input(input) => input,
            _ => panic!(),
        };

        let body = Body::Input(Input {
            file_id: Arc::clone(&file_id),
            block_checksums: {
                let reader = File::open(file).unwrap();
                // Pre-allocate block_checksums vector to eliminate the need for sorting
                let num_blocks: usize = length as usize / block_size;
                let mut block_checksums: Vec<([u8; 16], u32)> = vec![([0; 16], 0); num_blocks];

                // Iterate through file a byte at a time and collect
                // block_size bytes as chunks. Innumerate each chunk
                for (i, chunk) in reader.bytes().chunks(block_size).into_iter().enumerate() {
                    let block: Arc<Vec<u8>> = Arc::new(chunk.map(|x| x.unwrap()).collect());
                    let message_block = Arc::new(Block {
                        file_id: Arc::clone(&file_id),
                        index: i.clone(),
                        data: Arc::clone(&block),
                        // vec_length: block_size,
                        num_blocks: num_blocks,
                    });

                    tx_router
                        .send(Message::Block(Arc::clone(&message_block)))
                        .unwrap();

                    let tx_block = tx_block.clone();

                    spawn(move || {
                        let block = Arc::clone(&block);
                        let mut md5_sum = Vec::new();
                        let mut crc_sum = 0;

                        join(
                            || {
                                let mut hasher_md5 = Md5::new();
                                hasher_md5.input(&*block);
                                md5_sum = hasher_md5.result().to_vec();
                            },
                            || {
                                let mut hasher_crc32 = Hasher::new();
                                hasher_crc32.update(&*block);
                                crc_sum = hasher_crc32.finalize();
                            },
                        );

                        let result = (i, md5_sum, crc_sum);
                        tx_block.send(result).unwrap();
                    });
                }

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
    let mut senders: HashMap<&[u8; 16], Sender<Arc<Block>>> = HashMap::new();
    let mut buffers: HashMap<&[u8; 16], Buffer> = HashMap::new();
    let mut recvs = HashMap::new();

    for id in &*file_ids {
        let (tx, rx) = channel();
        senders.insert(id, tx);
        buffers.insert(id, Buffer::new());
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
                let tx = &senders[id];
                let mut buffer = buffers.get_mut(id).unwrap();
                match buffer.process(block) {
                    Some(block) => {
                        tx.send(Arc::clone(&block)).unwrap();

                        if buffer.is_done() {
                            drop(tx);
                        }

                        continue;
                    }
                    None => continue,
                }
            }
            _ => panic!("No valid message"),
        }
    }

    // spawn(move || {
    //     let hashers = Arc::clone(&hashers);
    //     for received in rx_file_description {

    //     }
    // });

    // for received in rx_fd {
    //     let tx_body = tx_body.clone();

    //     spawn(move || {
    //     let (name, length, hash_16k, file_id) = match received {
    //             Message::FileDescription(partial) => partial,
    //             _ => panic!(),
    //         };

    //         let body = Body::FileDescription(FileDescription {
    //             file_id: Arc::clone(&file_id),
    //             file_hash: {
    //                 let mut hasher = Md5::new();
    //                 let hash = convert_to_byte_array(hasher.result().to_vec());
    //                 hash
    //             },
    //             hash_16k: convert_to_byte_array(hash_16k),
    //             length: length,
    //             name: name,
    //         });

    //         tx_body.send(Message::Body(body)).unwrap();
    //     });
    // }
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
        static ref BLOCKS: Vec<Vec<u8>> = {
            let path = PathBuf::from(&PATH);
            let mut blocks = Vec::new();
            let reader = File::open(&path).unwrap();

            for chunk in reader.bytes().chunks(BLOCK_SIZE).into_iter() {
                let block: Vec<u8> = chunk.map(|x| x.unwrap()).collect();
                blocks.push(block.clone());
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
        let mut path_vec = Vec::new();
        let path = PathBuf::from(&PATH);
        let pipeline = CreatorPipeline::new();
        let (tx_router, rx_router) = channel();

        for _ in 0..1 {
            path_vec.push(path.to_owned());
        }

        let lock = pipeline.file_ids.write().unwrap();
        create_file_id(tx_router, path_vec, lock);
        // End setup

        // Test input channel
        for received in rx_router {
            match received {
                Message::Input(input) => {
                    let received = input;

                    // Test received
                    assert_eq!(
                        &*received.type_name_of(),
                        "(std::sync::Arc<[u8; 16]>, std::path::PathBuf, u64)",
                        "received type is wrong"
                    );

                    // Test file open
                    assert!(
                        {
                            match File::open(&received.1) {
                                Ok(_) => true,
                                Err(_) => false,
                            }
                        },
                        "Cannot open file"
                    );

                    // Test file_id hash
                    assert_eq!(
                        &received.0[..],
                        *FILE_ID, // file id hash
                        "File ID hash is wrong"
                    );

                    // Test length
                    assert_eq!(LENGTH, received.2, "File length is wrong.");
                }
                Message::FileDescription(fd) => {
                    let received = fd;
                    // Test partial body
                    assert_eq!(
                        received.type_name_of(),
                        "(std::vec::Vec<u8>, u64, std::boxed::Box<[u8; 16]>, std::sync::Arc<[u8; 16]>)",
                        "partial body is wrong type"
                    );

                    // Test name
                    assert_eq!(*NAME, received.0[..], "File name is wrong");
                    // Test first 16k hash
                    assert_eq!(
                        *HASH_16K,
                        received.2[..],
                        "Hash of first 16k is wrong"
                    );
                    // Test length
                    assert_eq!(LENGTH, received.1, "length is wrong");

                    // Test file_ids
                    let file_ids = pipeline.file_ids.read().unwrap();

                    for id in &*file_ids {
                        assert_eq!(id, &*FILE_ID);
                    }
                }
                _ => panic!("No valid message"),
            }
        }
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
