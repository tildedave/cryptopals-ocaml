open Batteries
open Bits
open Encoding
open Cryptokit

(*

Challenge 7 - AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.


*)

let run () =
  Printf.printf "*** CHALLENGE 7: AES in ECB mode ***\n";
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "7.txt")) in
  let key = "YELLOW SUBMARINE" in
  let plaintext = Crypto.aes_ecb_decrypt cipher key in
  assert (String.exists (Bytes.to_string plaintext) "Play that funky music white boy");
  let reencrypted = Crypto.aes_ecb_encrypt plaintext key in
  assert (String.equal (to_hex_string cipher) (to_hex_string reencrypted));
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;
