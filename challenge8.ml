open Batteries
open Bits
open Encoding
open Cryptokit

(*

Challenge 8 - Detect AES in ECB mode

In this file are a bunch of hex-encoded ciphertexts.

One of them has been encrypted with ECB.

Detect it.

Remember that the problem with ECB is that it is stateless and deterministic; the same 16 byte plaintext block will always produce the same 16 byte ciphertext.

*)

let run () =
  Printf.printf "*** CHALLENGE 8: Detect AES in ECB mode ***\n";
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
