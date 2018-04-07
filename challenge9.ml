open Encoding
open Batteries
open Util

(*

Challenge 1 - Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

*)

let run () =
  Printf.printf "*** CHALLENGE 9: Implement PKCS#7 padding ***\n";
  let s = pad_pkcs7 (Bytes.of_string "YELLOW SUBMARINE") 20 in
  assert (Char.code(Bytes.get s 16) == 4);
  assert (Char.code(Bytes.get s 17) == 4);
  assert (Char.code(Bytes.get s 18) == 4);
  assert (Char.code(Bytes.get s 19) == 4);
  Printf.printf "%s %d\n" (Bytes.to_string s) (Bytes.length s);
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;
