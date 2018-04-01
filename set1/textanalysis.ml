type text_analysis = {
  vector: bytes;
  num_vowels: int;
  num_spaces: int;
  most_frequent: char * int;
  freq_mapping: (char, int) Hashtbl.t ;
};;

let analyze_bytes bytes =
  let h = Hashtbl.create (Bytes.length bytes) in
  Bytes.iter (fun c ->
    if not (Hashtbl.mem h c) then
        Hashtbl.add h c 1
    else
        Hashtbl.add h c ((Hashtbl.find h c) + 1)
  ) bytes;
  let freq = List.sort (fun kv1 kv2 -> -1 * compare (snd kv1) (snd kv2)) (Util.hashtbl_items h) in
  { vector = bytes ;
    num_vowels = (
      Util.hashtbl_find_with_default h 'a' 0 +
      Util.hashtbl_find_with_default h 'e' 0 +
      Util.hashtbl_find_with_default h 'i' 0 +
      Util.hashtbl_find_with_default h 'o' 0 +
      Util.hashtbl_find_with_default h 'u' 0 ) ;
    num_spaces = Util.hashtbl_find_with_default h ' ' 0 ;
    most_frequent = List.hd freq ;
    freq_mapping = h
  }
