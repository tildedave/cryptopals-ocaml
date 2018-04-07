open Batteries
open Bits
open Encoding
open Cryptokit

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

let challenge3 () =
  Printf.printf "*** CHALLENGE 3: Single-byte XOR cipher ***\n";
  let s1 = from_hex_string "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736" in
  let (i, s, loser, candidate) = Decrypto.brute_force_single_xor s1 in
  Printf.printf "Best candidate was %d (score: %d; second-best: %d): %s\n" i s loser (Bytes.to_string candidate);
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
  let lines = File.lines_of "4.txt" in
  let (i, s, candidate) = BatEnum.fold (fun best_so_far line ->
      let (i, s, _, candidate) = Decrypto.brute_force_single_xor (from_hex_string line) in
      let (_, best_score, _) = best_so_far in
      if s > best_score then
        (i, s, candidate)
      else
        best_so_far
    ) (0, -1000, Bytes.create 0) lines in
  Printf.printf "Best candidate was %d (score: %d): %s\n" i s (Bytes.to_string candidate);
  assert (String.equal (Bytes.to_string candidate) "Now that the party is jumping\n");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

(*

Challenge 5 - Implement repeating-key XOR

Here is the opening stanza of an important work of the English language:

Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal
Encrypt it, under the key "ICE", using repeating-key XOR.

In repeating-key XOR, you'll sequentially apply each byte of the key; the first byte of plaintext will be XOR'd against I, the next C, the next E, then I again for the 4th byte, and so on.

It should come out to:

0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272
a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f
Encrypt a bunch of stuff using your repeating-key XOR function. Encrypt your mail. Encrypt your password file. Your .sig file. Get a feel for it. I promise, we aren't wasting your time with this.

*)

let challenge5 () =
  Printf.printf "*** CHALLENGE 5: Implement repeating-key XOR ***\n";
  let bytes = Bytes.of_string "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal" in
  assert (String.equal (to_hex_string (repeating_key_xor bytes "ICE")) "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

(*

Challenge 6 - Break repeating-key XOR

It is officially on, now.

This challenge isn't conceptually hard, but it involves actual error-prone coding. The other challenges in this set are there to bring you up to speed. This one is there to qualify you. If you can do this one, you're probably just fine up to Set 6.

There's a file here. It's been base64'd after being encrypted with repeating-key XOR.

Decrypt it.

Here's how:

Let KEYSIZE be the guessed length of the key; try values from 2 to (say) 40.
Write a function to compute the edit distance/Hamming distance between two strings. The Hamming distance is just the number of differing bits. The distance between:
this is a test
and
wokka wokka!!!
is 37. Make sure your code agrees before you proceed.
For each KEYSIZE, take the first KEYSIZE worth of bytes, and the second KEYSIZE worth of bytes, and find the edit distance between them. Normalize this result by dividing by KEYSIZE.
The KEYSIZE with the smallest normalized edit distance is probably the key. You could proceed perhaps with the smallest 2-3 KEYSIZE values. Or take 4 KEYSIZE blocks instead of 2 and average the distances.
Now that you probably know the KEYSIZE: break the ciphertext into blocks of KEYSIZE length.
Now transpose the blocks: make a block that is the first byte of every block, and a block that is the second byte of every block, and so on.
Solve each block as if it was single-character XOR. You already have code to do this.
For each block, the single-byte XOR key that produces the best looking histogram is the repeating-key XOR key byte for that block. Put them together and you have the key.
This code is going to turn out to be surprisingly useful later on. Breaking repeating-key XOR ("Vigenere") statistically is obviously an academic exercise, a "Crypto 101" thing. But more people "know how" to break it than can actually break it, and a similar technique breaks something much more important.

*)

let challenge6 () =
  Printf.printf "*** CHALLENGE 6: Break repeating-key XOR ***\n";
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "6.txt")) in
(*
  let _ = List.map (fun (ks, dist) ->
    Printf.printf "ks=%d = dist=%.2f " ks dist
  ) (Decrypto.guess_keysize cipher 40) in
*)
  let guessed_keysize = 29 in
  let key = Bytes.create guessed_keysize in
  let buckets = Util.split_bytes cipher guessed_keysize in
  begin
    List.iteri (fun k v ->
      let (i, s, loser, candidate) = Decrypto.brute_force_single_xor v in
      (*
      Printf.printf "Bucket %d - best candidate was %d (score: %d; loser: %d): %s\n" k i s loser (Bytes.to_string candidate);
      *)
      Bytes.set key k (Char.chr i)
    ) buckets;
    Printf.printf "key=%s\n" (Bytes.to_string key);
    let solution = repeating_key_xor cipher (Bytes.to_string key) in
    assert (String.equal (Bytes.to_string key) "Terminator X: Bring the noise");
    assert (String.exists (Bytes.to_string solution) "Play that funky music white boy");
    Printf.printf "🎉 All assertions complete! 🎉\n"
  end
;;

(*

Challenge 7 - AES in ECB mode
The Base64-encoded content in this file has been encrypted via AES-128 in ECB mode under the key

"YELLOW SUBMARINE".
(case-sensitive, without the quotes; exactly 16 characters; I like "YELLOW SUBMARINE" because it's exactly 16 bytes long, and now you do too).

Decrypt it. You know the key, after all.

Easiest way: use OpenSSL::Cipher and give it AES-128-ECB as the cipher.


*)

let challenge7 () =
  Printf.printf "*** CHALLENGE 7: AES in ECB mode ***\n";
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "7.txt")) in
  let key = "YELLOW SUBMARINE" in
  let aes_encrypt = Cipher.aes ~mode:ECB key Cipher.Decrypt in
  let s = transform_string aes_encrypt (Bytes.to_string cipher) in
  assert (String.exists s "Play that funky music white boy");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

(*

Challenge 8 - Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

*)

let num_repetitions bytes block_size =
  let hash_blocks = Hashtbl.create 20 in
  let repeated = ref 0 in
  for i = 0 to (Bytes.length bytes) - 1 - block_size do
    let s = (Bytes.sub bytes i block_size) in
    let v = (Hashtbl.find_default hash_blocks s 0) in
    Hashtbl.replace hash_blocks s (v + 1);
    if v > 0 then
      repeated := !repeated + 1
    else
      ()
  done;
  !repeated


let challenge8 () =
  let lines = BatEnum.map from_hex_string (File.lines_of "8.txt") in
  let winners = List.sort
    (fun k1 k2 -> -1 * compare (snd k1) (snd k2))
    (List.of_enum (BatEnum.mapi (fun n b ->
      let reps = List.fold_left (+) 0 (List.map (num_repetitions b) (Util.range 3 30)) in
        (n, reps)
      ) lines)) in
    let (winner, score) = List.hd winners in
    let (_, runner_up_score) = List.nth winners 1 in
    Printf.printf "%d is the winner with score %d! (runner_up_score: %d)\n" winner score runner_up_score;
    assert (winner == 132);
    Printf.printf "🎉 All assertions complete! 🎉\n"
;;