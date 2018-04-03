open Bits

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
    (i, Bits.fixed_xor s1 s2)) (Util.range 0 256))

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
  ) (List.tl (Util.range 0 (keysize_max - 1)))
