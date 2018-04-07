open Batteries
open Bits
open Encoding
open Cryptokit

(*

Challenge 4 - Detect single-character XOR
One of the 60-character strings in this file has been encrypted by single-character XOR.

Find it.

(Your code from #3 should help.)

*)

let run () =
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
