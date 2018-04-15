open Bits

type mode = CBC | ECB
let mode_to_string mode = match mode with CBC -> "CBC" | ECB -> "ECB"

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

let ctr_stream_cipher key nonce ciphertext =
  let cipher_length = Bytes.length ciphertext in
  let blocksize = 16 in
  let i = ref 0 in
  let counter = ref nonce in
  let b = ref (Bytes.create 0) in
  while !i < cipher_length - 1 do
    let num_bytes = (min blocksize (cipher_length - !i - 1)) in
    let current_text = Bytes.init blocksize (fun n -> Char.chr (if n == 8 then !counter else 0)) in
    let keystream = transform_bytes (aes_encrypt key) current_text in
    let current_block = Bytes.sub ciphertext !i num_bytes in
    b := Bytes.cat !b (Bits.fixed_xor (Bytes.sub keystream 0 num_bytes) current_block);
    counter := !counter + 1;
    i := !i + blocksize
  done;
  !b
