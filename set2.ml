open Encoding
open Batteries
open Util

(*

Challenge 1 - Implement PKCS#7 padding

A block cipher transforms a fixed-sized block (usually 8 or 16 bytes) of plaintext into ciphertext. But we almost never want to transform a single block; we encrypt irregularly-sized messages.

One way we account for irregularly-sized messages is by padding, creating a plaintext that is an even multiple of the blocksize. The most popular padding scheme is called PKCS#7.

So: pad any block to a specific block length, by appending the number of bytes of padding to the end of the block. For instance,

*)

let challenge9 () =
  Printf.printf "*** CHALLENGE 1: Implement PKCS#7 padding ***\n";
  let s = pad_pkcs7 (Bytes.of_string "YELLOW SUBMARINE") 20 in
  assert (Char.code(Bytes.get s 16) == 4);
  assert (Char.code(Bytes.get s 17) == 4);
  assert (Char.code(Bytes.get s 18) == 4);
  assert (Char.code(Bytes.get s 19) == 4);
  Printf.printf "%s %d\n" (Bytes.to_string s) (Bytes.length s);
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;

(*

Challenge 2 - Implement CBC mode

CBC mode is a block cipher mode that allows us to encrypt irregularly-sized messages, despite the fact that a block cipher natively only transforms individual blocks.

In CBC mode, each ciphertext block is added to the next plaintext block before the next call to the cipher core.

The first plaintext block, which has no associated previous ciphertext block, is added to a "fake 0th ciphertext block" called the initialization vector, or IV.

Implement CBC mode by hand by taking the ECB function you wrote earlier, making it encrypt instead of decrypt (verify this by decrypting whatever you encrypt to test), and using your XOR function from the previous exercise to combine them.

The file here is intelligible (somewhat) when CBC decrypted against "YELLOW SUBMARINE" with an IV of all ASCII 0 (\x00\x00\x00 &c)

*)

let challenge10 () =
  Printf.printf "*** CHALLENGE 2: Implement CBC mode ***\n";
  let iv = Bytes.make 16 (Char.chr 0) in
  let s = Crypto.aes_cbc_encrypt (Bytes.of_string "YELLOW SUBMARINE") "YELLOW SUBMARINE" iv in
  let d = Crypto.aes_cbc_decrypt s "YELLOW SUBMARINE" iv in
  assert (String.equal (Bytes.to_string d) "YELLOW SUBMARINE");
  let cipher = from_base64_string (BatEnum.fold (^) "" (File.lines_of "10.txt")) in
  let decrypted = Crypto.aes_cbc_decrypt cipher "YELLOW SUBMARINE" iv in
  let reencrypted = Crypto.aes_cbc_encrypt decrypted "YELLOW SUBMARINE" iv in
  assert (String.equal (to_hex_string cipher) (to_hex_string reencrypted));
  assert (String.exists (Bytes.to_string decrypted) "Play that funky music white boy");
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;


(*

Challenge 11 - An ECB/CBC detection oracle

Now that you have ECB and CBC working:

Write a function to generate a random AES key; that's just 16 random bytes.

Write a function that encrypts data under an unknown key --- that is, a function that generates a random key and encrypts under it.

The function should look like:

encryption_oracle(your-input)
=> [MEANINGLESS JIBBER JABBER]
Under the hood, have the function append 5-10 bytes (count chosen randomly) before the plaintext and 5-10 bytes after the plaintext.

Now, have the function choose to encrypt under ECB 1/2 the time, and under CBC the other half (just use random IVs each time for CBC). Use rand(2) to decide which to use.

Detect the block cipher mode the function is using each time. You should end up with a piece of code that, pointed at a block box that might be encrypting ECB or CBC, tells you which one is happening.

*)

type mode = CBC | ECB
let mode_to_string mode = match mode with CBC -> "CBC" | ECB -> "ECB"

let encryption_oracle input force_ecb =
  let random_key = Bytes.to_string (Bits.random_bytes 16) in
  let (prepend, append) = mapt2 Bits.random_bytes (Random.int 5 + 5, Random.int 5 + 5) in
  let fuzzed_input = Bytes.cat (Bytes.cat prepend input) append in
  let padded_input = pad_to_blocksize pad_pkcs7 input 16 in
  if Random.bool () || force_ecb then
    (ECB, Crypto.aes_ecb_encrypt padded_input random_key)
  else
    (CBC, Crypto.aes_cbc_encrypt padded_input random_key (Bytes.make 16 (Char.chr 0)))

let challenge11 () =
  Printf.printf "*** CHALLENGE 2: An ECB/CBC Detection Oracle ***\n";
  Random.self_init ();
  let s = Crypto.aes_ecb_encrypt (Bytes.of_string "YELLOW SUBMARINE") "YELLOW SUBMARINE" in
  let d = Crypto.aes_ecb_decrypt s "YELLOW SUBMARINE" in
  assert (String.equal (Bytes.to_string d) "YELLOW SUBMARINE");
  let sample = Bytes.of_string (BatEnum.fold (^) "" (File.lines_of "lorem.txt")) in
  let percent_repetitions cipher size =
    let num_repetitions = Bits.num_repetitions cipher size in
    let num_blocks = (Bytes.length cipher) / size in
    Printf.printf "-> %d %d %d %.4f\n" size num_repetitions num_blocks (float(num_repetitions) /. float(num_blocks));
    float(num_repetitions) /. float(num_blocks) in
  for i = 1 to 4 do
    let (mode, ciphertext) = encryption_oracle sample true in
    let _ = Printf.printf "%s\n" (mode_to_string mode) in
    (List.iter (fun n ->
      Printf.printf "-> %d %d\n"
      n
      (Bits.num_repetitions ciphertext n)) (Util.range 3 30))
(*         let threshold = 0.01 in
        let guess =
          match List.find_opt
            (fun p -> p > threshold)
            (List.map (percent_repetitions ciphertext) (Util.range 3 30)) with
          | None -> CBC
          | (Some _) -> ECB
        in
          ()
 *)(*           if guess == mode then
            Printf.printf "Guessed correctly! :) mode=%s, guess=%s\n" (mode_to_string mode) (mode_to_string guess)
          else
            Printf.printf "Guessed incorrectly! :( mode=%s, guess=%s\n" (mode_to_string mode) (mode_to_string guess)
 *)      done
;;
