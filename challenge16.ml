open Batteries
open Bits
open Encoding
open Util

(*
CBC bitflipping attacks
Generate a random AES key.

Combine your padding code and CBC code to write two functions.

The first function should take an arbitrary input string, prepend the string:

"comment1=cooking%20MCs;userdata="
.. and append the string:

";comment2=%20like%20a%20pound%20of%20bacon"
The function should quote out the ";" and "=" characters.

The function should then pad out the input to the 16-byte AES block length and encrypt it under the random AES key.

The second function should decrypt the string and look for the characters ";admin=true;" (or, equivalently, decrypt, split the string on ";", convert each resulting string into 2-tuples, and look for the "admin" tuple).

Return true or false based on whether the string exists.

If you've written the first function properly, it should not be possible to provide user input to it that will generate the string the second function is looking for. We'll have to break the crypto to do that.

Instead, modify the ciphertext (without knowledge of the AES key) to accomplish this.

You're relying on the fact that in CBC mode, a 1-bit error in a ciphertext block:

Completely scrambles the block the error occurs in
Produces the identical 1-bit error(/edit) in the next ciphertext block.

*)

let random_key = Bytes.to_string (Bits.random_bytes 16)
let iv = Bits.random_bytes 16

let escape_string str =
  String.replace_chars (fun c ->
    match c with
    | ';' -> "%59"
    | '=' -> "%61"
  | _ -> String.make 1 c) str

let rec unescape_string str =
  (replace_all (replace_all str "%59" ";") "%61" "=")

let encrypt_user_data user_data =
  let prefix, suffix = mapt2 Bytes.of_string ("comment1=cooking%20MCs;userdata=",
                                              ";comment2=%20like%20a%20pound%20of%20bacon") in
  let escaped_user_data = Bytes.of_string (escape_string user_data) in
  Crypto.aes_cbc_encrypt
    (pad_to_blocksize pad_pkcs7 (Bytes.cat (Bytes.cat prefix escaped_user_data) suffix) 16)
    random_key
    iv

let is_admin ciphertext =
  let plaintext = Crypto.aes_cbc_decrypt ciphertext random_key iv in
  String.exists (Bytes.to_string plaintext) ";role=admin;"

let run () =
  Printf.printf "*** CHALLENGE 16: CBC bitflipping attacks ***\n";
  assert_strings_equal (escape_string "comment1=bananas;") "comment1%61bananas%59";
  assert_strings_equal (unescape_string (escape_string "comment1=bananas;")) "comment1=bananas;";
  let equal_flip, semi_flip = mapt2 String.of_char (lxor_char '=' (Char.chr 8), lxor_char ';' (Char.chr 8)) in
  let attack_text = semi_flip ^ "role" ^ equal_flip ^ "admin" ^ semi_flip in
  let ciphertext = encrypt_user_data attack_text in
  let mod_block = nth_block ciphertext 1 16 in
  bytes_xor mod_block 0 (Char.chr 8);
  bytes_xor mod_block 5 (Char.chr 8);
  bytes_xor mod_block 11 (Char.chr 8);
  replace_block ciphertext mod_block 1 16;
  assert (is_admin ciphertext);
  Printf.printf "🎉 All assertions complete! 🎉\n";
  ()
