(* Utility functions *)

let mapt2 f (a, b) = (f a, f b)
let mapt3 f (a, b, c) = (f a, f b, f c)
let mapt4 f (a, b, c, d) = (f a, f b, f c, f d)

let hashtbl_items h = Hashtbl.fold (fun k v l -> (k, v) :: l)  h []
let hashtbl_find_with_default h k d =
    match Hashtbl.find_opt h k with
    | None -> d
    | Some v -> v
