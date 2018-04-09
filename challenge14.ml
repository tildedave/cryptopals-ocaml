open Batteries
open Decrypto
open Encoding

(*

Byte-at-a-time ECB decryption (Harder)
Take your oracle function from #12. Now generate a random count of random bytes and prepend this string to every plaintext. You are now doing:

AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
Same goal: decrypt the target-bytes.

Stop and think for a second.
What's harder than challenge #12 about doing this? How would you overcome that obstacle? The hint is: you're using all the tools you already have; no crazy math is required.

Think "STIMULUS" and "RESPONSE".
*)


let _ = Random.self_init ()
let random_key = Bytes.to_string (Bits.random_bytes 16)
let magic_text = (BatEnum.fold (^) "" (File.lines_of "12.txt"))
let fixed_prefix = Bits.random_bytes (Random.int 32 + 16)

let encryption_oracle input =
  let combined_input = (Bytes.cat input (from_base64_string magic_text)) in
  let fuzzed_input = Bytes.cat fixed_prefix combined_input in
  let padded_input = pad_to_blocksize pad_pkcs7 fuzzed_input 16 in
  Crypto.aes_ecb_encrypt padded_input random_key


let find_prefix_length encryption_func blocksize =
  let block = Bits.random_bytes blocksize in
  let input = Bits.repeat_block block 2 in
  let i = ref 0 in
  let j = ref 0 in
  try
    while !i < blocksize do
      let aligned_input = Bytes.cat (Bytes.make (!i) '0') input in
      let ciphertext = encryption_func aligned_input in
      j := 0;
      while !j < (Bytes.length ciphertext - blocksize * 2) do
        let first_block = (Bytes.sub ciphertext (blocksize + !j) blocksize) in
        let second_block = (Bytes.sub ciphertext ((blocksize * 2) + !j) blocksize) in
        if Bytes.equal first_block second_block  then
          raise Exit
        else
          j := !j + blocksize
      done;
      i := !i + 1
    done;
    assert false
  with Exit -> blocksize - !i + !j

let run () =
  Printf.printf "*** CHALLENGE 14: Byte-at-a-time ECB decryption (Harder) ***\n";
  let blocksize = Decrypto.guess_blocksize encryption_oracle in
  let prefix_length = find_prefix_length encryption_oracle blocksize in
  let secret_length = guess_secret_length encryption_oracle blocksize prefix_length in
  let decrypted = List.fold_left (fun bytes n ->
    let b = guess_byte encryption_oracle bytes prefix_length blocksize in
    Bytes.cat bytes (Bytes.make 1 (Char.chr b)))
    (Bytes.create 0)
    (Util.range 0 secret_length) in
  assert (String.equal (Bytes.to_string decrypted) (Bytes.to_string (from_base64_string magic_text)));
  assert (String.exists (Bytes.to_string decrypted) "The girlies on standby waving just to say hi");
  Printf.printf "🎉 All assertions complete! 🎉\n"
