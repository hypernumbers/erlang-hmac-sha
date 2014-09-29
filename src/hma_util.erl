-module(hma_util).

-export([
         get_header/2,
         canonicalise_headers/2,
         normalise/1
        ]).


%% @doc find the value of a header out of mochiweb_headers() structure
%%
%% If the header is not set, it returns ""
get_header(Headers, Type) ->
    case lists:keyfind(Type, 1, Headers) of
        false   -> "";
        {_K, V} -> V
    end.

%% @doc normalize a set of HTTP Headers represented as a proplist
%% where the key can be either a string or an atom.
%%
%% It returns a proplist where all the keys are strings
%%
-spec normalise(List :: list({atom() | string(), string()})) ->
  list({string(), string()}).
normalise(List) -> norm2(List, []).

norm2([], Acc) -> Acc;
norm2([{K, V} | T], Acc) when is_atom(K) ->
    norm2(T, [{string:to_lower(atom_to_list(K)), V} | Acc]);
norm2([H | T], Acc) -> norm2(T, [H | Acc]).


%% @doc convert all headers into a canonical form:
%% 1. Sort the headers
%% 2. Lowercase all the keys
%% 3. Filter out all headers that do not being with a given
%%    prefix (default is 'x-hmac')
%% 4. concatenate all the strings, separated by '\n'
%% 5. terminate concatenated headers by '\n'
canonicalise_headers(Prefix, List) ->
    List2 = [{string:to_lower(K), V} || {K, V} <- lists:sort(List)],
    c_headers2(Prefix, consolidate(List2, []), []).


%%
%% Helper functions
%%
c_headers2(_Prefix, [], Acc) ->
    string:join(Acc, "\n") ++ "\n";
c_headers2(Prefix, [{Header, Key} | T], Acc) ->
    case lists:prefix(Prefix, Header) of
        true ->
            Hd = string:strip(Header) ++ ":" ++ string:strip(Key),
            c_headers2(Prefix, T, [Hd | Acc]);
        false ->
            c_headers2(Prefix, T, Acc)
    end.

consolidate([H | []], Acc) -> [H | Acc];
consolidate([{H, K1}, {H, K2} | Rest], Acc) ->
    consolidate([{H, join(K1, K2)} | Rest], Acc);
consolidate([{H1, K1}, {H2, K2} | Rest], Acc) ->
    consolidate([{rectify(H2), rectify(K2)} | Rest], [{H1, K1} | Acc]).

join(A, B) -> string:strip(A) ++ ";" ++ string:strip(B).

%% removes line spacing as per RFC 2616 Section 4.2
rectify(String) ->
    Re = "[\x20* | \t*]+",
    re:replace(String, Re, " ", [{return, list}, global]).

