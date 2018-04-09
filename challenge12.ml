open Batteries
open Crypto
open Decrypto
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

let run () =
  Printf.printf "*** CHALLENGE 12: Byte-at-a-time ECB decryption (Simple) ***\n";
  let blocksize = guess_blocksize encryption_oracle in
  if is_ecb encryption_oracle blocksize then
    begin
      let secret_length = guess_secret_length encryption_oracle blocksize 0 in
      let decrypted = List.fold_left (fun bytes n ->
        let b = guess_byte encryption_oracle bytes 0 blocksize in
        Bytes.cat bytes (Bytes.make 1 (Char.chr b)))
        (Bytes.create 0)
        (Util.range 0 secret_length) in
        assert (String.equal (Bytes.to_string decrypted) (Bytes.to_string (from_base64_string magic_text)))
    end
  else
    assert false;
  ();
  Printf.printf "🎉 All assertions complete! 🎉\n"
