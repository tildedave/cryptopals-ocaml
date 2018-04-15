open Encoding
open Util

(*

Implement CTR, the stream cipher mode
The string:

L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==
... decrypts to something approximating English in CTR mode, which is an AES block cipher mode that turns AES into a stream cipher, with the following parameters:

      key=YELLOW SUBMARINE
      nonce=0
      format=64 bit unsigned little endian nonce,
             64 bit little endian block count (byte count / 16)
CTR mode is very simple.

Instead of encrypting the plaintext, CTR mode encrypts a running counter, producing a 16 byte block of keystream, which is XOR'd against the plaintext.

For instance, for the first 16 bytes of a message with these parameters:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00")
... for the next 16 bytes:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00")
... and then:

keystream = AES("YELLOW SUBMARINE",
                "\x00\x00\x00\x00\x00\x00\x00\x00\x02\x00\x00\x00\x00\x00\x00\x00")
CTR mode does not require padding; when you run out of plaintext, you just stop XOR'ing keystream and stop generating keystream.

Decryption is identical to encryption. Generate the same keystream, XOR, and recover the plaintext.

Decrypt the string at the top of this function, then use your CTR function to encrypt and decrypt other things.

This is the only block cipher mode that matters in good code.
Most modern cryptography relies on CTR mode to adapt block ciphers into stream ciphers, because most of what we want to encrypt is better described as a stream than as a sequence of blocks. Daniel Bernstein once quipped to Phil Rogaway that good cryptosystems don't need the "decrypt" transforms. Constructions like CTR are what he was talking about.

*)


let ctr_stream_cipher key nonce ciphertext =
  let cipher_length = Bytes.length ciphertext in
  let key_bytes = Bytes.of_string key in
  let blocksize = 16 in
  let num_blocks = cipher_length / blocksize in
  let i = ref 0 in
  let counter = ref nonce in
  let b = ref (Bytes.create 0) in
  while !i < cipher_length - 1 do
    let num_bytes = (min blocksize (cipher_length - !i - 1)) in
    let current_key = Bytes.init blocksize (fun n -> Char.chr (if n == 8 then !counter else 0)) in
    let keystream = Crypto.aes_ecb_encrypt current_key key in
    let current_block = Bytes.sub ciphertext !i num_bytes in
    b := Bytes.cat !b (Bits.fixed_xor (Bytes.sub keystream 0 num_bytes) current_block);
    counter := !counter + 1;
    i := !i + blocksize
  done;
  !b

let run () =
  Printf.printf "*** CHALLENGE 18: Implement CTR, the stream cipher mode ***\n";
  let cool_string = "L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==" in
  let plaintext = ctr_stream_cipher "YELLOW SUBMARINE" 0 (from_base64_string cool_string) in
  Printf.printf "%s\n" (Bytes.to_string plaintext);
  assert_strings_equal (Bytes.to_string plaintext) "Yo, VIP Let's kick it Ice, Ice, baby Ice, Ice, baby I";
  let ciphertext = ctr_stream_cipher "YELLOW SUBMARINE" 0 plaintext in
  assert_strings_equal (to_base64_string ciphertext) cool_string;
  Printf.printf "🎉 All assertions complete! 🎉\n";
  ()
