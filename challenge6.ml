open Batteries
open Bits
open Encoding
open Util

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

let split_bytes bytes size =
  let buckets = Hashtbl.create size in
    List.iter (fun k -> Hashtbl.add buckets k Bytes.empty) (range 0 size);
    Bytes.iteri (fun n c ->
      let k = n mod size in
      let bucket = Hashtbl.find buckets k in
      (* this is stupid inefficient *)
      Hashtbl.replace buckets k (Bytes.cat bucket (Bytes.make 1 c))
    ) bytes;
    List.fold_left (fun acc n -> Hashtbl.find buckets n :: acc) [] (List.rev (range 0 size))

let run () =
  Printf.printf "*** CHALLENGE 6: Break repeating-key XOR ***\n";
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "6.txt")) in
  let guessed_keysize = 29 in
  let key = Bytes.create guessed_keysize in
  let buckets = split_bytes cipher guessed_keysize in
  begin
    List.iteri (fun k v ->
      let (i, s, loser, candidate) = Decrypto.brute_force_single_xor v in
      Bytes.set key k (Char.chr i)
    ) buckets;
    Printf.printf "key=%s\n" (Bytes.to_string key);
    let solution = repeating_key_xor cipher (Bytes.to_string key) in
    assert (String.equal (Bytes.to_string key) "Terminator X: Bring the noise");
    assert (String.exists (Bytes.to_string solution) "Play that funky music white boy");
    Printf.printf "🎉 All assertions complete! 🎉\n"
  end
;;
