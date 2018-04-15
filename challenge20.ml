open Batteries
open Bits
open Encoding
open Util

(*

Break fixed-nonce CTR statistically
In this file find a similar set of Base64'd plaintext. Do with them exactly what you did with the first, but solve the problem differently.

Instead of making spot guesses at to known plaintext, treat the collection of ciphertexts the same way you would repeating-key XOR.

Obviously, CTR encryption appears different from repeated-key XOR, but with a fixed nonce they are effectively the same thing.

To exploit this: take your collection of ciphertexts and truncate them to a common length (the length of the smallest ciphertext will work).

Solve the resulting concatenation of ciphertexts as if for repeating- key XOR, with a key size of the length of the ciphertext you XOR'd.

*)

let split_bytes byte_list size =
  let buckets = Hashtbl.create size in
    List.iter (fun k -> Hashtbl.add buckets k Bytes.empty) (range 0 size);
    List.iter (fun bytes ->
      Bytes.iteri
        (fun n c ->
          let bucket = Hashtbl.find buckets n in
          (* this is stupid inefficient *)
          Hashtbl.replace buckets n (Bytes.cat bucket (Bytes.make 1 c)))
        bytes)
      byte_list;
    List.fold_left (fun acc n -> Hashtbl.find buckets n :: acc) [] (List.rev (range 0 size))

let break_fixed_nonce_ctr ciphers =
  let keysize = List.fold_left
    (fun acc bytes -> let len = Bytes.length bytes in if len < acc then len else acc)
    Int.max_num
    ciphers in
  let truncated_ciphers = List.map (fun bytes -> Bytes.sub bytes 0 keysize) ciphers in
  let keystream = Bytes.create keysize in
  let buckets = split_bytes truncated_ciphers keysize in
  List.iteri (fun n v ->
    let (i, score, loser_score, candidate) = Decrypto.brute_force_single_xor v in
    Bytes.set keystream n (Char.chr i)
  ) buckets;
  List.map (fun bytes -> fixed_xor keystream bytes) truncated_ciphers

let run () =
  Printf.printf "*** CHALLENGE 20: Break fixed-nonce CTR statistically ***\n";
  let ciphers = List.of_enum (BatEnum.map from_base64_string (File.lines_of "20.txt")) in
  let decrypted_ciphers = break_fixed_nonce_ctr ciphers in
  List.iteri (fun n line -> Printf.printf "n=%d line=%s\n" n (Bytes.to_string line))
    (List.take 5 decrypted_ciphers);
  assert_strings_equal "i'm rated \"R\"...this is a warning, ya better void / Po"
    (Bytes.to_string (List.nth decrypted_ciphers 0));
  assert_strings_equal "this is off limits, so your visions are blurry / All y"
    (Bytes.to_string (List.nth decrypted_ciphers 9));
  (* let's test this method on the strings from challenge 19 too *)
  let decrypted_challenge19_ciphers = break_fixed_nonce_ctr Challenge19.encrypted_lines in
  List.iteri (fun n line -> Printf.printf "n=%d line=%s\n" n (Bytes.to_string line))
    (List.take 5 decrypted_challenge19_ciphers);
  assert_strings_equal "i have met them at c"
    (Bytes.to_string (List.nth decrypted_challenge19_ciphers 0));
  Printf.printf "🎉 All assertions complete! 🎉\n";
  ()
