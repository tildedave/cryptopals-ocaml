open Encoding
open Batteries

(*

Challenge 1 - Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

*)

let challenge9 () =
  Printf.printf "*** CHALLENGE 1: Implement PKCS#7 padding ***\n";
  let s = pad_pkcs7 (Bytes.of_string "YELLOW SUBMARINE") 20 in
  assert (Char.code(Bytes.get s 16) == 4);
  assert (Char.code(Bytes.get s 17) == 4);
  assert (Char.code(Bytes.get s 18) == 4);
  assert (Char.code(Bytes.get s 19) == 4);
  Printf.printf "%s %d\n" (Bytes.to_string s) (Bytes.length s);
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

(*

Challenge 2 - Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

*)

let challenge10 () =
  Printf.printf "*** CHALLENGE 2: Implement CBC mode ***\n";
  let iv = Bytes.make 16 (Char.chr 0) in
  let s = Crypto.cbc_encrypt (Bytes.of_string "YELLOW SUBMARINE") "YELLOW SUBMARINE" iv in
  let d = Crypto.cbc_decrypt s "YELLOW SUBMARINE" iv in
  assert (String.equal (Bytes.to_string d) "YELLOW SUBMARINE");
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "10.txt")) in
  let decrypted = Crypto.cbc_decrypt cipher "YELLOW SUBMARINE" iv in
  let reencrypted = Crypto.cbc_encrypt decrypted "YELLOW SUBMARINE" iv in
  assert (String.equal (to_hex_string cipher) (to_hex_string reencrypted));
  assert (String.exists (Bytes.to_string decrypted) "Play that funky music white boy");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;
