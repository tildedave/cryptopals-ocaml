open Batteries
open Bits
open Encoding
open Padding
open Util

(*

The CBC padding oracle
This is the best-known attack on modern block-cipher cryptography.

Combine your padding code and your CBC code to write two functions.

The first function should select at random one of the following 10 strings:

MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=
MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=
MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==
MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==
MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl
MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==
MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==
MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=
MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=
MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93
... generate a random AES key (which it should save for all future encryptions), pad the string out to the 16-byte AES block size and CBC-encrypt it under that key, providing the caller the ciphertext and IV.

The second function should consume the ciphertext produced by the first function, decrypt it, check its padding, and return true or false depending on whether the padding is valid.

What you're doing here.
This pair of functions approximates AES-CBC encryption as its deployed serverside in web applications; the second function models the server's consumption of an encrypted session token, as if it was a cookie.

It turns out that it's possible to decrypt the ciphertexts provided by the first function.

The decryption here depends on a side-channel leak by the decryption function. The leak is the error message that the padding is valid or not.

You can find 100 web pages on how this attack works, so I won't re-explain it. What I'll say is this:

The fundamental insight behind this attack is that the byte 01h is valid padding, and occur in 1/256 trials of "randomized" plaintexts produced by decrypting a tampered ciphertext.

02h in isolation is not valid padding.

02h 02h is valid padding, but is much less likely to occur randomly than 01h.

03h 03h 03h is even less likely.

So you can assume that if you corrupt a decryption AND it had valid padding, you know what that padding byte is.

It is easy to get tripped up on the fact that CBC plaintexts are "padded". Padding oracles have nothing to do with the actual padding on a CBC plaintext. It's an attack that targets a specific bit of code that handles decryption. You can mount a padding oracle on any CBC block, whether it's padded or not.

*)

let options = [
  "MDAwMDAwTm93IHRoYXQgdGhlIHBhcnR5IGlzIGp1bXBpbmc=";
  "MDAwMDAxV2l0aCB0aGUgYmFzcyBraWNrZWQgaW4gYW5kIHRoZSBWZWdhJ3MgYXJlIHB1bXBpbic=";
  "MDAwMDAyUXVpY2sgdG8gdGhlIHBvaW50LCB0byB0aGUgcG9pbnQsIG5vIGZha2luZw==";
  "MDAwMDAzQ29va2luZyBNQydzIGxpa2UgYSBwb3VuZCBvZiBiYWNvbg==";
  "MDAwMDA0QnVybmluZyAnZW0sIGlmIHlvdSBhaW4ndCBxdWljayBhbmQgbmltYmxl";
  "MDAwMDA1SSBnbyBjcmF6eSB3aGVuIEkgaGVhciBhIGN5bWJhbA==";
  "MDAwMDA2QW5kIGEgaGlnaCBoYXQgd2l0aCBhIHNvdXBlZCB1cCB0ZW1wbw==";
  "MDAwMDA3SSdtIG9uIGEgcm9sbCwgaXQncyB0aW1lIHRvIGdvIHNvbG8=";
  "MDAwMDA4b2xsaW4nIGluIG15IGZpdmUgcG9pbnQgb2g=";
  "MDAwMDA5aXRoIG15IHJhZy10b3AgZG93biBzbyBteSBoYWlyIGNhbiBibG93";
]

let chosen_ciphertext = ref (Bytes.create 0)

let random_key = Bytes.to_string (Bits.random_bytes 16)

let encrypt_function () =
  let iv = Bits.random_bytes 16 in
  chosen_ciphertext := from_base64_string (Random.choice (List.enum options));
  (Crypto.aes_cbc_encrypt
    (pad_to_blocksize pad_pkcs7 !chosen_ciphertext 16)
    random_key
    iv, iv)

let check_padding ciphertext iv =
  let plaintext = Crypto.aes_cbc_decrypt ciphertext random_key iv in
  try
    let _ = strip_pkcs7_padding plaintext 16 in true
  with Bad_Padding -> false

let next_byte_via_padding_oracle block target_block known blocksize =
  let len_known = Bytes.length known in
  let padding_char = Char.chr (len_known + 1) in
  let block_copy = Bytes.copy block in
  let target_idx = blocksize - len_known - 1 in
  let current_char = Bytes.get block target_idx in
  let c = ref 0 in
  (if len_known > 0 then
    for i = blocksize - 1 downto blocksize - len_known do
      let known_byte = Bytes.get known (blocksize - i - 1) in
      let intermediate = lxor_char known_byte (Bytes.get block i) in
      let flipped_byte = lxor_char intermediate padding_char in
      Bytes.set block_copy i flipped_byte
    done
  else
    ());
  try
    while !c < 256 do
      let chr = Char.chr !c in
      (if current_char <> chr then
        (Bytes.set block_copy target_idx chr;
        if check_padding target_block block_copy then
          raise Exit
        else
          ())
       else
        ());
      c := !c + 1
    done;
    c := Char.code current_char;
    raise Exit
  with Exit ->
    lxor_char
      (lxor_char (Char.chr !c) padding_char)
      (Bytes.get block (blocksize - len_known - 1))

let run () =
  Printf.printf "*** CHALLENGE 17: The CBC padding oracle ***\n";
  let ciphertext, iv = encrypt_function () in
  let blocksize = 16 in
  assert (check_padding ciphertext iv);
  let decode_block i =
    let prev_block = if i == 0 then iv else nth_block ciphertext (i - 1) blocksize in
    let block = nth_block ciphertext i blocksize in
    List.fold_left
    (fun known n ->
      let next_char = next_byte_via_padding_oracle prev_block block known blocksize in
      Bytes.cat known (Bytes.make 1 next_char))
    (Bytes.create 0)
    (Util.range 0 blocksize) in
  let decoded_ciphertext =
    List.fold_left (fun acc n ->
      Bytes.cat acc (reverse_bytes (decode_block n)))
    (Bytes.create 0)
    (Util.range 0 (num_blocks ciphertext blocksize)) in
  Printf.printf "decoded_ciphertext=%s\n" (Bytes.to_string (strip_pkcs7_padding decoded_ciphertext blocksize));
  Printf.printf "chosen_ciphertext=%s\n" (Bytes.to_string !chosen_ciphertext);
  assert_bytes_equal (strip_pkcs7_padding decoded_ciphertext blocksize) !chosen_ciphertext;
  Printf.printf "🎉 All assertions complete! 🎉\n";
  ()
