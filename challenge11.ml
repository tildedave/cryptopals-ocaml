open Encoding
open Batteries
open Padding
open Util
open Crypto

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

let encryption_oracle input =
  let random_key = Bytes.to_string (Bits.random_bytes 16) in
  let (prepend, append) = mapt2 Bits.random_bytes (Random.int 5 + 5, Random.int 5 + 5) in
  let fuzzed_input = Bytes.cat (Bytes.cat prepend input) append in
  let padded_input = pad_to_blocksize pad_pkcs7 fuzzed_input 16 in
  if Random.bool () then
    (ECB, Crypto.aes_ecb_encrypt padded_input random_key)
  else
    (CBC, Crypto.aes_cbc_encrypt padded_input random_key (Bytes.make 16 (Char.chr 0)))

let run () =
  Printf.printf "*** CHALLENGE 11: An ECB/CBC Detection Oracle ***\n";
  Random.self_init ();
  let s = Crypto.aes_ecb_encrypt (Bytes.of_string "YELLOW SUBMARINE") "YELLOW SUBMARINE" in
  let d = Crypto.aes_ecb_decrypt s "YELLOW SUBMARINE" in
  assert (String.equal (Bytes.to_string d) "YELLOW SUBMARINE");
  let pathological_input = Bytes.make 1024 (Char.chr 0) in
  let block_size = 16 in
  let num_guesses = 100 in
  let guessed_right = ref 0 in
  for i = 1 to num_guesses do
    let mode, ciphertext = encryption_oracle pathological_input in
    let guess = if (Bits.num_repetitions ciphertext block_size) > 0 then ECB else CBC in
    if guess == mode then
      guessed_right := !guessed_right + 1
    else
      ()
  done;
  assert (!guessed_right == num_guesses);
  Printf.printf "🎉 All assertions complete! 🎉\n"
;;
