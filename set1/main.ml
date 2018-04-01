open Encoding
open Bits

(*

Challenge 1 - Convert hex to base64

The string:

49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d
Should produce:

SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t
So go ahead and make that happen. You'll need to use this code for the rest of the exercises.

Cryptopals Rule
Always operate on raw bytes, never on encoded strings. Only use hex and base64 for pretty-printing.

*)

let challenge1 () =
    Printf.printf "*** CHALLENGE 1: Convert hex to base64 ***\n";
    let challenge1_hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" in
    let challenge1_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" in
    assert (String.equal "4927" (to_hex_string (from_hex_string "4927")));
    assert (String.equal "SSdt" (to_base64_string (from_base64_string "SSdt")));
    assert (String.equal (to_base64_string (from_hex_string challenge1_hex_string)) challenge1_base64_string);
    assert (String.equal (to_hex_string (from_base64_string challenge1_base64_string)) challenge1_hex_string);
    Printf.printf "🎉 All assertions complete! 🎉\n";;

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

let challenge2 () =
    Printf.printf "*** CHALLENGE 2: Fixed XOR ***\n";
    let s1 = from_hex_string "1c0111001f010100061a024b53535009181c" in
    let s2 = from_hex_string "686974207468652062756c6c277320657965" in
    assert (String.equal (to_hex_string (fixed_xor s1 s2)) "746865206b696420646f6e277420706c6179");;
    Printf.printf "🎉 All assertions complete! 🎉\n";;

challenge1 ();;
challenge2 ();;
