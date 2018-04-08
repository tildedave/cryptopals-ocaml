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
  let fuzzed_input = Bytes.cat prepend input in
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

let get_cbc_end_block bytes blocksize =
  (* Take an array of pathological input and find the first block that deviates from the pattern *)
  let i = find_first_repeat bytes 0 blocksize in
  let j = find_last_repeat bytes i blocksize in
  Bytes.sub bytes (j + 1) blocksize

let get_cbc_pattern_block bytes blocksize =
  (* Take an array of pathological input and find the block that forms the pattern *)
  let i = find_first_repeat bytes 0 blocksize in
  Bytes.sub bytes i blocksize

let run () =
  Printf.printf "*** CHALLENGE 14: Byte-at-a-time ECB decryption (Harder) ***\n";
  let blocksize = Decrypto.guess_blocksize encryption_oracle in
  (* for different random padding we will need larger pathological size inputs *)
  let pathological_size = 1024 in
  let pathological_input = Bytes.make pathological_size 'A' in
  let great_hashtable = Hashtbl.create 1000 in
  for i = 0 to 1000
  do
    let block = get_cbc_end_block (encryption_oracle pathological_input) blocksize in
    let v = Hashtbl.find_default great_hashtable block 0 in
    Hashtbl.replace great_hashtable block (v + 1)
  done;
  let repetition_table = Hashtbl.filter (fun v -> v > 1) great_hashtable in
  Hashtbl.iter (fun k v ->
    if v > 1 then
      Printf.printf "k=%s v=%d\n" (to_hex_string k) v
    else
      ()
  ) repetition_table;
  (* guess first byte by brute forcing AAA + 1 char and seeing if it's in our repetition map *)
  let rec brute_force_guess c =
    assert (c < 256);
    let pathological_input = Bytes.make pathological_size 'A' in
    let num_iterations = 500 in
    let repetitions = ref 0 in
    let pattern = get_cbc_pattern_block (encryption_oracle pathological_input) blocksize in
    Printf.printf "%s\n" (to_hex_string pattern);
    Bytes.set pathological_input (pathological_size - 1) (Char.chr c);
    for i = 0 to num_iterations
    do
      let block = get_cbc_end_block (encryption_oracle pathological_input) blocksize in
      if Hashtbl.mem repetition_table block then
        (Printf.printf "found a repeition!! %s\n" (to_hex_string block);
        repetitions := !repetitions + 1)
      else
        ()
    done;
    if !repetitions > 0 then
      (Printf.printf "found a repetition! %c %d %d\n" (Char.chr c) c (!repetitions); c)
    else
      brute_force_guess (c + 1) in
  brute_force_guess 0;
  ()
