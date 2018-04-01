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

type text_analysis = {
    num_vowels: int;
    num_spaces: int;
    most_frequent: char * int;
    freq_mapping: (char, int) Hashtbl.t ;
};;

let challenge3 () =
    Printf.printf "*** CHALLENGE 3: Single-byte XOR cipher ***\n";
    let s1 = from_hex_string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" in
    let analyze_bytes bytes =
        let h = Hashtbl.create (Bytes.length bytes) in
        Bytes.iter (fun c ->
            if not (Hashtbl.mem h c) then
                Hashtbl.add h c 1
            else
                Hashtbl.add h c ((Hashtbl.find h c) + 1)
        ) bytes;
        let freq = List.sort (fun kv1 kv2 -> -1 * compare (snd kv1) (snd kv2)) (Util.hashtbl_items h) in
        { num_vowels = (
              Util.hashtbl_find_with_default h 'a' 0 +
              Util.hashtbl_find_with_default h 'e' 0 +
              Util.hashtbl_find_with_default h 'i' 0 +
              Util.hashtbl_find_with_default h 'o' 0 +
              Util.hashtbl_find_with_default h 'u' 0
          ) ;
          num_spaces = Util.hashtbl_find_with_default h ' ' 0 ;
          most_frequent = List.hd freq ;
          freq_mapping = h
        } in
    let best_candidate = ref (0, -1000, Bytes.create (Bytes.length s1)) in
    for i = 0 to 255 do
        let s2 = Bytes.make (Bytes.length s1) (Char.chr i) in
        let xor_vector = fixed_xor s1 s2 in
        let ta = analyze_bytes xor_vector in
        let score = ta.num_vowels + ta.num_spaces in
        let (_, best_so_far, _) = !best_candidate in
        if score > best_so_far then
            best_candidate := (i, score, xor_vector)
        else
            ()
    done;
    let (i, s, candidate) = !best_candidate in
    Printf.printf "Best candidate was %d (score: %d): %s\n" i s (Bytes.to_string candidate);
    assert (String.equal (Bytes.to_string candidate) "Cooking MC's like a pound of bacon");
    Printf.printf "🎉 All assertions complete! 🎉\n";;

challenge1 ();;
challenge2 ();;
challenge3 ();;
