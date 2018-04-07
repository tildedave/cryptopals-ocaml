open Batteries
open Bits
open Encoding
open Cryptokit

(*

Challenge 2 - Fixed XOR

Write a function that takes two equal-length buffers and produces their XOR combination.

If your function works properly, then when you feed it the string:

1c0111001f010100061a024b53535009181c
... after hex decoding, and when XOR'd against:

686974207468652062756c6c277320657965
... should produce:

746865206b696420646f6e277420706c6179

*)

let run () =
  Printf.printf "*** CHALLENGE 2: Fixed XOR ***\n";
  let s1 = from_hex_string "1c0111001f010100061a024b53535009181c" in
  let s2 = from_hex_string "686974207468652062756c6c277320657965" in
  assert (String.equal (to_hex_string (fixed_xor s1 s2)) "746865206b696420646f6e277420706c6179");
  Printf.printf "🎉 All assertions complete! 🎉\n";;
