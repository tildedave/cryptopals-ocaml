open Encoding
open Batteries
open Util

(*

Challenge 10 - Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

*)

let run () =
  Printf.printf "*** CHALLENGE 10: Implement CBC mode ***\n";
  let iv = Bytes.make 16 (Char.chr 0) in
  let s = Crypto.aes_cbc_encrypt (Bytes.of_string "YELLOW SUBMARINE") "YELLOW SUBMARINE" iv in
  let d = Crypto.aes_cbc_decrypt s "YELLOW SUBMARINE" iv in
  assert (String.equal (Bytes.to_string d) "YELLOW SUBMARINE");
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "10.txt")) in
  let decrypted = Crypto.aes_cbc_decrypt cipher "YELLOW SUBMARINE" iv in
  let reencrypted = Crypto.aes_cbc_encrypt decrypted "YELLOW SUBMARINE" iv in
  assert (String.equal (to_hex_string cipher) (to_hex_string reencrypted));
  assert (String.exists (Bytes.to_string decrypted) "Play that funky music white boy");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;
