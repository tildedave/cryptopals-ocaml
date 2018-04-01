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
  assert (String.equal (to_hex_string (fixed_xor s1 s2)) "746865206b696420646f6e277420706c6179");
  Printf.printf "🎉 All assertions complete! 🎉\n";;

(*

Challenge 3 - Single-byte XOR cipher

The hex encoded string:

1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736
... has been XOR'd against a single character. Find the key, decrypt the message.

You can do this by hand. But don't: write code to do it for you.

How? Devise some method for "scoring" a piece of English plaintext. Character frequency is a good metric. Evaluate each output and choose the one with the best score.


*)

let choose_best_analysis vector_list =
  let best_candidate = (0, -1000, Bytes.create 0) in
  List.fold_right (fun vec best_candidate ->
    let ta = Textanalysis.analyze_bytes (snd vec) in
    let score = ta.num_vowels + ta.num_spaces in
    let (_, best_so_far, _) = best_candidate in
    if score > best_so_far then
      (fst vec, score, snd vec)
    else
      best_candidate
  ) vector_list best_candidate;;

let brute_force_single_xor s1 = List.map (fun i ->
    let s2 = Bytes.make (Bytes.length s1) (Char.chr i) in
    (i, fixed_xor s1 s2)) (Util.range 256)

let challenge3 () =
  Printf.printf "*** CHALLENGE 3: Single-byte XOR cipher ***\n";
  let s1 = from_hex_string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" in
  let vector_list = brute_force_single_xor s1 in
  let (i, s, candidate) = choose_best_analysis vector_list in
  Printf.printf "Best candidate was %d (score: %d): %s\n" i s (Bytes.to_string candidate);
  assert (String.equal (Bytes.to_string candidate) "Cooking MC's like a pound of bacon");
  Printf.printf "🎉 All assertions complete! 🎉\n";;

(*

Challenge 4 - Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

*)

let challenge4 () =
  Printf.printf "*** CHALLENGE 4: Detect single-character XOR ***\n";
  let ic = open_in "4.txt" in
  let overall_best = ref (0, -1000, Bytes.create 0) in
  try
    while true do
      let line = input_line ic in
      let (i, s, candidate) = choose_best_analysis (brute_force_single_xor (from_hex_string line)) in
      let (_, best_score, _) = !overall_best in
        if s > best_score then
          overall_best := (i, s, candidate)
        else
          ()
    done
  with End_of_file ->
    close_in ic;
  let (i, s, candidate) = !overall_best in
  Printf.printf "Best candidate was %d (score: %d): %s\n" i s (Bytes.to_string candidate);
  assert (String.equal (Bytes.to_string candidate) "Now that the party is jumping\n");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

challenge1 ();;
challenge2 ();;
challenge3 ();;
challenge4 ();;
