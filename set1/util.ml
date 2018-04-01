(* Utility functions *)

let mapt2 f (a, b) = (f a, f b)
let mapt3 f (a, b, c) = (f a, f b, f c)
let mapt4 f (a, b, c, d) = (f a, f b, f c, f d)

let hashtbl_items h = Hashtbl.fold (fun k v l -> (k, v) :: l)  h []
let hashtbl_find_with_default h k d =
  match Hashtbl.find_opt h k with
  | None -> d
  | Some v -> v

let range n =
  let rec range_helper i j =
    if i == j then [] else i :: range_helper (i + 1) j
  in
    assert (n > 0);
    range_helper 0 n

let slurp_file filename =
  let ic = open_in filename in
  let s = ref [] in
  begin
    try
      while true do
        let line = input_line ic in
        s := line :: !s
      done
    with End_of_file ->
      close_in ic
  end;
  List.rev (!s)
