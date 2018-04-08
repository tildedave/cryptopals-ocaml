open Batteries
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


let random_key = Bytes.to_string (Bits.random_bytes 16)
let magic_text = (BatEnum.fold (^) "" (File.lines_of "12.txt"))

let encryption_oracle input =
  let combined_input = (Bytes.cat input (from_base64_string magic_text)) in
  let prepend = Bits.random_bytes (Random.int 8 + 5) in
  let fuzzed_input = Bytes.cat prepend combined_input in
  let padded_input = pad_to_blocksize pad_pkcs7 fuzzed_input 16 in
  Crypto.aes_ecb_encrypt padded_input random_key

let rec find_first_repeat bytes i blocksize =
  if Bytes.equal (Bytes.sub bytes i blocksize) (Bytes.sub bytes (i + blocksize) blocksize) then
    i
  else
    find_first_repeat bytes (i + blocksize) blocksize

let rec find_last_repeat bytes i blocksize =
  if Bytes.equal (Bytes.sub bytes i blocksize) (Bytes.sub bytes (i + blocksize) blocksize) then
    find_last_repeat bytes (i + blocksize) blocksize
  else
    i

let get_ecb_end_block bytes blocksize =
  (* Take an array of pathological input and find the first block that deviates from the pattern *)
  let i = find_first_repeat bytes 0 blocksize in
  let j = find_last_repeat bytes i blocksize in
  Bytes.sub bytes (j + blocksize) blocksize

let get_ecb_pattern_block bytes blocksize =
  (* Take an array of pathological input and find the block that forms the pattern *)
  let i = find_first_repeat bytes 0 blocksize in
  Bytes.sub bytes i blocksize

(* goal is to see if we can get a block that matches the end block by inserting our own padding
     at the start, then  *)
let guess_byte known blocksize repetition_table =
  let rec helper c =
    assert (c < 256);
    let pathological_block, pathological_size = Bytes.make blocksize 'A', 256 in
    (* TODO copy appropriate block from known *)
    Bytes.set pathological_block (blocksize - 1) (Char.chr c);
    let repeated_block_input = Bits.repeat_block pathological_block (pathological_size / blocksize) in
    let num_iterations = 500 in
    let repetitions = ref 0 in
    for i = 0 to num_iterations do
      let padsize = Random.int blocksize in
      let chopped_input = Bytes.sub repeated_block_input padsize (Bytes.length repeated_block_input - padsize) in
      let pattern_block = get_ecb_pattern_block (encryption_oracle chopped_input) blocksize in
      if Hashtbl.mem repetition_table pattern_block then
        repetitions := (!repetitions) + 1
      else
        ()
    done;
    if !repetitions > 0 then
      (* done, found it *)
      c
    else
      helper (c + 1) in
  helper 0

let run () =
  Printf.printf "*** CHALLENGE 14: Byte-at-a-time ECB decryption (Harder) ***\n";
  let blocksize = Decrypto.guess_blocksize encryption_oracle in
  (* for different random padding we will need larger pathological size inputs *)
  let pathological_size = 256 in
  let pathological_input = Bytes.make pathological_size 'A' in
  let test_ciphertext = (encryption_oracle pathological_input) in
  Printf.printf "%s pattern block: %s end block: %s\n"
    (to_hex_string test_ciphertext)
    (to_hex_string (get_ecb_pattern_block test_ciphertext blocksize))
    (to_hex_string (get_ecb_end_block test_ciphertext blocksize));
  let repetition_table = Hashtbl.create 1000 in
  for i = 0 to 1000
  do
    let random_padding = Bits.random_bytes (Random.int blocksize) in
    let fuzzed_input = Bytes.sub pathological_input 0 (pathological_size - Bytes.length random_padding) in
    let ciphertext = encryption_oracle fuzzed_input in
    let block = get_ecb_end_block ciphertext blocksize in
    let v = Hashtbl.find_default repetition_table block 0 in
    Hashtbl.replace repetition_table block (v + 1)
  done;
  Hashtbl.iter (fun k v ->
    if v > 1 then
      Printf.printf "k=%s v=%d\n" (to_hex_string k) v
    else
      ()
  ) repetition_table;
  Printf.printf "%d\n" (guess_byte (Bytes.create 0) blocksize repetition_table);
  ()
