open Batteries
open Crypto
open Encoding
open Util

(*

Byte-at-a-time ECB decryption (Simple)
Copy your oracle function to a new function that encrypts buffers under ECB mode using a consistent but unknown key (for instance, assign a single random key, once, to a global variable).

Now take that same function and have it append to the plaintext, BEFORE ENCRYPTING, the following string:

Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK
Spoiler alert.
Do not decode this string now. Don't do it.

Base64 decode the string before appending it. Do not base64 decode the string by hand; make your code do it. The point is that you don't know its contents.

What you have now is a function that produces:

AES-128-ECB(your-string || unknown-string, random-key)
It turns out: you can decrypt "unknown-string" with repeated calls to the oracle function!

Here's roughly how:

Feed identical bytes of your-string to the function 1 at a time --- start with 1 byte ("A"), then "AA", then "AAA" and so on. Discover the block size of the cipher. You know it, but do this step anyway.
Detect that the function is using ECB. You already know, but do this step anyways.
Knowing the block size, craft an input block that is exactly 1 byte short (for instance, if the block size is 8 bytes, make "AAAAAAA"). Think about what the oracle function is going to put in that last byte position.
Make a dictionary of every possible last byte by feeding different strings to the oracle; for instance, "AAAAAAAA", "AAAAAAAB", "AAAAAAAC", remembering the first block of each invocation.
Match the output of the one-byte-short input to one of the entries in your dictionary. You've now discovered the first byte of unknown-string.
Repeat for the next byte.

*)

let random_key = Bytes.to_string (Bits.random_bytes 16)
let magic_text = (BatEnum.fold (^) "" (File.lines_of "12.txt"))

let encryption_oracle input =
  let combined_input = (Bytes.cat input (from_base64_string magic_text)) in
  let padded_input = pad_to_blocksize pad_pkcs7 combined_input 16 in
  Crypto.aes_ecb_encrypt padded_input random_key

let guess_secret_length encryption_func =
  let i, cont = ref 0, ref true in
  let initial_cipher = (encryption_func (Bytes.create 0)) in
  let last_cipher = ref initial_cipher in
  while (!i) < 64 && !cont do
    let cipher = encryption_func (Bytes.make (!i) 'A') in
    if Bytes.length cipher > Bytes.length (!last_cipher) then
      cont := false
    else
      begin
        i := !i + 1;
        last_cipher := cipher
      end
  done;
  assert (!i < 64);
  (Bytes.length initial_cipher) - !i + 1

let guess_byte known blocksize =
  let i = Bytes.length known in
  let which_block = i / blocksize in
  let bytes = Bytes.make (blocksize * (which_block + 1)) 'A' in
  let num_bytes = Bytes.length bytes in
  Bytes.blit known 0 bytes (num_bytes - i - 1) i;
  let all_options_hash = Hashtbl.create 256 in
  for c = 0 to 255 do
    Bytes.set bytes (num_bytes - 1) (Char.chr c);
    let encrypted_block = Bits.nth_block (encryption_oracle bytes) which_block blocksize in
    Hashtbl.replace all_options_hash encrypted_block c
  done;
  assert ((Hashtbl.length all_options_hash) == 256);
  let input = (Bytes.make (num_bytes - i - 1) 'A') in
  let block = Bits.nth_block (encryption_oracle input) which_block blocksize in
  Hashtbl.find all_options_hash block

let run () =
  Printf.printf "*** CHALLENGE 12: Byte-at-a-time ECB decryption (Simple) ***\n";
  let blocksize = Decrypto.guess_blocksize encryption_oracle in
  if Decrypto.is_ecb encryption_oracle blocksize then
    begin
      let secret_length = guess_secret_length encryption_oracle in
      let decrypted = List.fold_left (fun bytes n ->
        let b = guess_byte bytes blocksize in
        Bytes.cat bytes (Bytes.make 1 (Char.chr b)))
        (Bytes.create 0)
        (Util.range 0 secret_length) in
        assert (String.equal (Bytes.to_string decrypted) (Bytes.to_string (from_base64_string magic_text)))
    end
  else
    assert false;
  ();
  Printf.printf "🎉 All assertions complete! 🎉\n"
