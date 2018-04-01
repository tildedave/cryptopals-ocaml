open Bits

let choose_best_analysis vector_list =
  let best_candidate = (0, -1000, Bytes.create 0) in
  List.fold_right (fun vec best_candidate ->
    let ta = Textanalysis.analyze_bytes (snd vec) in
    let score = ta.num_vowels + ta.num_spaces in
    let (_, best_so_far, _) = best_candidate in
    if score > best_so_far then
      (fst vec, score, snd vec)
    else
      best_candidate
  ) vector_list best_candidate;;

let brute_force_single_xor s1 =
  choose_best_analysis (List.map (fun i ->
    let s2 = Bytes.make (Bytes.length s1) (Char.chr i) in
    (i, Bits.fixed_xor s1 s2)) (Util.range 256))

let guess_keysize s keysize_max =
  List.map (fun keysize ->
    let s1 = Bytes.sub s 0 keysize in
    let s2 = Bytes.sub s keysize (keysize * 2) in
    (keysize, hamming_distance s1 s2)
  ) (Util.range (keysize_max - 1))
