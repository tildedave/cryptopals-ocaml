open Bits
open Util

let choose_best_analysis vector_list =
  let best_candidate = (0, -1000, -1000, Bytes.create 0) in
  List.fold_right (fun vec best_candidate ->
    let ta = Textanalysis.analyze_bytes (snd vec) in
    let score = Textanalysis.score ta in
    let (_, best_so_far, _, _) = best_candidate in
    if score > best_so_far then
      begin
        (fst vec, score, best_so_far, snd vec)
      end
    else
      best_candidate
  ) vector_list best_candidate;;

let brute_force_single_xor s1 =
  choose_best_analysis (List.map (fun i ->
    let s2 = Bytes.make (Bytes.length s1) (Char.chr i) in
    (i, Bits.fixed_xor s1 s2)) (range 0 256))

let guess_keysize s keysize_max =
  List.map (fun keysize ->
    let s1 = Bytes.sub s 0 keysize in
    let s2 = Bytes.sub s keysize keysize in
    let s3 = Bytes.sub s (keysize * 2) keysize in
    let s4 = Bytes.sub s (keysize * 3) keysize in
    let s5 = Bytes.sub s (keysize * 4) keysize in
      (keysize,
        (List.fold_left (+.) 0.0
        (List.map
          (fun (s1, s2) -> float (hamming_distance s1 s2) /. (8.0 *. (float keysize)))
          [(s1, s2) ;  (s2, s3);  (s3, s4) ; (s4, s5)]) /. 4.0))
  ) (List.tl (range 0 (keysize_max - 1)))

let guess_blocksize encryption_func =
  List.fold_left
    (fun acc n ->
      let input = Bytes.make n 'A' in
      gcd acc (Bytes.length (encryption_func input)))
    (Bytes.length (encryption_func (Bytes.create 0)))
    (range 1 64)

let is_ecb encryption_func blocksize =
  let pathological_input = Bytes.make 1024 'A' in
  Bits.num_repetitions (encryption_func pathological_input) blocksize > 0

let guess_secret_length encryption_func blocksize prefix_length =
  let i = ref 0 in
  let initial_cipher = encryption_func (Bytes.create 0) in
  let last_cipher = ref initial_cipher in
  try
    while !i < 64 do
      let cipher = encryption_func (Bytes.make (!i) 'A') in
      if Bytes.length cipher > Bytes.length (!last_cipher) then
        raise Exit
      else
        begin
          i := !i + 1;
          last_cipher := cipher
        end
    done;
    assert false
  with Exit ->
  begin
    assert (!i < 64);
    (Bytes.length initial_cipher) - !i + 1 - prefix_length
  end

let guess_byte encryption_func known prefix_length blocksize =
  let i = Bytes.length known in
  let which_block = i / blocksize in
  let prefix_block =
    if blocksize > prefix_length then
      Bytes.make (blocksize - prefix_length) '0'
    else
      Bytes.make (imod (blocksize - prefix_length) blocksize) '0' in
  let prefix_offset = prefix_length / blocksize in
  let bytes = Bytes.cat prefix_block (Bytes.make (blocksize * (which_block + 1)) 'A') in
  let num_bytes = Bytes.length bytes in
  Bytes.blit known 0 bytes (num_bytes - i - 1) i;
  let all_options_hash = Hashtbl.create 256 in
  for c = 0 to 255 do
    Bytes.set bytes (num_bytes - 1) (Char.chr c);
    let ciphertext = (encryption_func bytes) in
    let encrypted_block = Bits.nth_block ciphertext (which_block + prefix_offset + 1) blocksize in
    Hashtbl.replace all_options_hash encrypted_block c
  done;
  assert ((Hashtbl.length all_options_hash) == 256);
  (* should not need to return the prefix here *)
  let input = (Bytes.make (num_bytes - i - 1) 'A') in
  let block = Bits.nth_block (encryption_func input) (which_block + prefix_offset + 1) blocksize in
  Hashtbl.find all_options_hash block
