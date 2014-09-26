-module(hma_util).

-export([
         get_header/2,
         normalise/1
        ]).


get_header(Headers, Type) ->
    case lists:keyfind(Type, 1, Headers) of
        false   -> "";
        {_K, V} -> V
    end.

normalise(List) -> norm2(List, []).

norm2([], Acc) -> Acc;
norm2([{K, V} | T], Acc) when is_atom(K) ->
    norm2(T, [{string:to_lower(atom_to_list(K)), V} | Acc]);
norm2([H | T], Acc) -> norm2(T, [H | Acc]).

