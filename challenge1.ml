open Encoding

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

let run () =
  Printf.printf "*** CHALLENGE 1: Convert hex to base64 ***\n";
  let challenge1_hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d" in
  let challenge1_base64_string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t" in
  assert (String.equal "4927" (to_hex_string (from_hex_string "4927")));
  assert (String.equal "SSdt" (to_base64_string (from_base64_string "SSdt")));
  assert (String.equal (to_base64_string (from_hex_string challenge1_hex_string)) challenge1_base64_string);
  assert (String.equal (to_hex_string (from_base64_string challenge1_base64_string)) challenge1_hex_string);
  Printf.printf "🎉 All assertions complete! 🎉\n";;
