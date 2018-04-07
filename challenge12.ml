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
  let combined_input = (Bytes.cat input (Bytes.of_string magic_text)) in
  let padded_input = pad_to_blocksize pad_pkcs7 combined_input 16 in
  Crypto.aes_ecb_encrypt padded_input random_key

let guess_blocksize encryption_func =
  List.fold_left
    (fun acc n ->
      let input = Bytes.make n 'A' in
      gcd acc (Bytes.length (encryption_func input)))
    (Bytes.length (encryption_func (Bytes.create 0)))
    (Util.range 1 64)

let is_ecb encryption_func blocksize =
  let pathological_input = Bytes.make 1024 'A' in
  Bits.num_repetitions (encryption_func pathological_input) blocksize > 0

let run () =
  Printf.printf "*** CHALLENGE 12: Byte-at-a-time ECB decryption (Simple) ***\n";
  let blocksize = guess_blocksize encryption_oracle in
  let first_block bytes = Bytes.sub bytes 0 blocksize in
  if is_ecb encryption_oracle blocksize then
    begin
      let all_options_hash = Hashtbl.create 256 in
      let bytes = Bytes.make blocksize 'A' in
      for i = 0 to 255 do
        Bytes.set bytes (blocksize - 1) (Char.chr i);
        let encrypted_block = first_block (encryption_oracle bytes) in
        Hashtbl.replace all_options_hash encrypted_block i
      done;
      let block = (first_block (encryption_oracle (Bytes.make (blocksize - 1) 'A'))) in
      let guessed_first_byte = Hashtbl.find all_options_hash block in
      Printf.printf "Guessed first byte is %d\n" guessed_first_byte
    end
  else
    assert false;
  ()
