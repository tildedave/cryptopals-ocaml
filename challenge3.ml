open Batteries
open Bits
open Encoding
open Cryptokit

(*

Challenge 3 - Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.


*)

let run () =
  Printf.printf "*** CHALLENGE 3: Single-byte XOR cipher ***\n";
  let s1 = from_hex_string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" in
  let (i, s, loser, candidate) = Decrypto.brute_force_single_xor s1 in
  Printf.printf "Best candidate was %d (score: %d; second-best: %d): %s\n" i s loser (Bytes.to_string candidate);
  assert (String.equal (Bytes.to_string candidate) "Cooking MC's like a pound of bacon");
  Printf.printf "🎉 All assertions complete! 🎉\n";;
