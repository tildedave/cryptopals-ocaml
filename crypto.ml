open Bits

let aes_encrypt key = Cryptokit.Cipher.aes ~mode:ECB key Cryptokit.Cipher.Encrypt
let aes_decrypt key = Cryptokit.Cipher.aes ~mode:ECB key Cryptokit.Cipher.Decrypt

let cbc_process_block transform block previous_block =
  Bytes.of_string (Cryptokit.transform_string transform (Bytes.to_string (fixed_xor block previous_block)))

let cbc_process transform bytes iv =
  let bytes_len = Bytes.length bytes in
  let bytes_block = Bytes.create bytes_len in
  let block_size = 16 in
  begin
    assert (bytes_len mod block_size == 0);
    let i = ref 0 in
    let last_block = ref iv in
    while !i < bytes_len do
      let block = Bytes.sub bytes (!i) block_size in
      let transform_block = cbc_process_block transform block (!last_block) in
        last_block := transform_block;
        Bytes.blit transform_block 0 bytes_block (!i) block_size;
        i := !i + block_size
    done;
    bytes_block
  end

let cbc_encrypt bytes key iv = cbc_process (aes_encrypt key) bytes iv
let cbc_decrypt bytes key iv = cbc_process (aes_decrypt key) bytes iv
