open Bits

let aes_encrypt key = Cryptokit.Cipher.aes ~mode:ECB key Cryptokit.Cipher.Encrypt
let aes_decrypt key = Cryptokit.Cipher.aes ~mode:ECB key Cryptokit.Cipher.Decrypt

let transform_bytes transform bytes =
  Bytes.of_string (Cryptokit.transform_string transform (Bytes.to_string bytes))

let aes_ecb_encrypt bytes key = transform_bytes (aes_encrypt key) bytes
let aes_ecb_decrypt bytes key = transform_bytes (aes_decrypt key) bytes

let aes_cbc_decrypt bytes key iv =
  let bytes_len = Bytes.length bytes in
  let bytes_block = Bytes.create bytes_len in
  let block_size = 16 in
  begin
    assert (bytes_len mod block_size == 0);
    let i = ref 0 in
    let last_block = ref iv in
    while !i < bytes_len do
      let block = Bytes.sub bytes (!i) block_size in
      let transform_block = transform_bytes (aes_decrypt key) block in
      let decrypted_block = fixed_xor transform_block (!last_block) in
        Bytes.blit decrypted_block 0 bytes_block (!i) block_size;
        last_block := block;
        i := !i + block_size
    done;
    bytes_block
  end

let aes_cbc_encrypt bytes key iv =
  let bytes_len = Bytes.length bytes in
  let bytes_block = Bytes.create bytes_len in
  let block_size = 16 in
  begin
    assert (bytes_len mod block_size == 0);
    let i = ref 0 in
    let last_block = ref iv in
    while !i < bytes_len do
      let block = Bytes.sub bytes (!i) block_size in
      let encrypted_block = transform_bytes (aes_encrypt key) (fixed_xor !last_block block) in
        Bytes.blit encrypted_block 0 bytes_block (!i) block_size;
        last_block := encrypted_block;
        i := !i + block_size
    done;
    bytes_block
  end
