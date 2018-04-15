open Batteries

type text_analysis = {
  vector: bytes;
  num_vowels: int;
  num_spaces: int;
  num_alphabet: int;
  num_non_alphabet: int;
  num_common: int;
  most_frequent_10: char list;
  freq_mapping: (char, int) Hashtbl.t ;
};;

let analyze_bytes bytes =
  let h = Hashtbl.create (Bytes.length bytes) in
  Bytes.iter (fun c ->
    if not (Hashtbl.mem h c) then
        Hashtbl.add h c 1
    else
        Hashtbl.replace h c ((Hashtbl.find h c) + 1)
  ) bytes;
  let freq = List.sort (fun kv1 kv2 -> -1 * compare (snd kv1) (snd kv2)) (Util.hashtbl_items h) in
  let sum_over_hash = fun acc c -> Hashtbl.find_default h c 0 + acc in
  let num_alphabet = List.fold_left (fun acc k ->
      Util.hashtbl_find_with_default h (Char.chr k) 0 + acc) 0 (Util.range 31 125) in
  { vector = bytes ;
    num_alphabet = num_alphabet;
    num_non_alphabet = Bytes.length bytes - num_alphabet ;
    num_vowels = (
      List.fold_left sum_over_hash 0 ['a'; 'e'; 'i'; 'o'; 'u']
    );
    num_common = (
      List.fold_left sum_over_hash 0 ['e';'t';'a';'o';'i';'n';'s';'r']
    );
    num_spaces = Util.hashtbl_find_with_default h ' ' 0 ;
    most_frequent_10 = List.map fst (Util.take freq 10);
    freq_mapping = h
  }

  let score ta = ta.num_common + ta.num_spaces + ta.num_vowels - ta.num_non_alphabet * 10

let to_string ta =
  Printf.sprintf "text_analysis: {\n\tnum_vowels = %d,\n\tnum_spaces = %d,\n\tnum_alphabet = %d,\n\tmost_frequent_10 = %s,\n\tscore = %d,\n}"
    ta.num_vowels
    ta.num_spaces
    ta.num_alphabet
    ((List.fold_left (fun acc c -> acc ^ " " ^ String.of_char c) "[ " ta.most_frequent_10) ^ "]")
    (score ta)
