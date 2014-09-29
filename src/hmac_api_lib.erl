-module(hmac_api_lib).

-include("hmac_api.hrl").

-include_lib("eunit/include/eunit.hrl").
-ifdef(TEST).
-compile(export_all).
-endif.

-author("Hypernumbers Ltd <gordon@hypernumbers.com>").

%%% this library supports the hmac_sha api on both the client-side
%%% AND the server-side
%%%
%%% sign/6 is used client-side to sign a request
%%% - it returns an HTTPAuthorization header
%%%
%%% [mochi_|cowboy_]authorize_request/3 takes a Request and both keys
%%  as arguements and checks that the request matches the signature
%%%
%%% get_api_keypair/0 creates a pair of public/private keys
%%%
%%% THIS LIB DOESN'T IMPLEMENT THE AMAZON API IT ONLY IMPLEMENTS
%%% ENOUGH OF IT TO GENERATE A TEST SUITE.
%%%
%%% THE AMAZON API MUNGES HOSTNAME AND PATHS IN A CUSTOM WAY
%%% THIS IMPLEMENTATION DOESN'T
-export([
         sign/5,
         sign/6,

         validate/4,

         get_api_keypair/0,

         parse_authorization_header/1
        ]).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%                                                                          %%%
%%% API                                                                      %%%
%%%                                                                          %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

sign(PrivateKey, PublicKey, Method, URL, Headers) ->
    sign(#hmac_config{}, PrivateKey, PublicKey, Method, URL, Headers).
sign(#hmac_config{schema = Schema} = Config, PrivateKey, PublicKey, Method, URL, Headers) ->
    Headers2 = hma_util:normalise(Headers),
    ContentType = hma_util:get_header(Headers2, "Content-Type"),
    ContentMD5 = hma_util:get_header(Headers2, "Content-MD5"),
    Date = hma_util:get_header(Headers2, "Date"),
    Signature = #hmac_signature{config = Config,
                                method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    SignedSig = sign_data(PrivateKey, Signature),
    make_HTTPAuth_header(Schema, SignedSig, PublicKey).

-spec validate(PrivateKey :: string(),
               PublicKey :: string(),
               Authorization :: string(),
               Signature :: #hmac_signature{}) -> match | no_match.
validate(PrivateKey, PublicKey, Authorization, #hmac_signature{config = #hmac_config{schema = Schema}} = Signature) ->
    Signed = sign_data(PrivateKey, Signature),
    {_, AuthHeader} = make_HTTPAuth_header(Schema, Signed, PublicKey),
    case AuthHeader of
        Authorization ->
            match;
        _       ->
            no_match
    end.

-spec get_api_keypair() -> {string(), string()}.
get_api_keypair() ->
    Public  = mochihex:to_hex(binary_to_list(crypto:strong_rand_bytes(16))),
    Private = mochihex:to_hex(binary_to_list(crypto:strong_rand_bytes(16))),
    {format(Public), format(Private)}.

-spec parse_authorization_header(Header :: string()) -> {string(), string(), string()}.
parse_authorization_header(Header) ->
    [Schema, Tail] = string:tokens(Header, " "),
    [PublicKey, Signature] = string:tokens(Tail, ":"),
    {Schema, PublicKey, Signature}.

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%                                                                          %%%
%%% Internal Functions                                                       %%%
%%%                                                                          %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%

make_HTTPAuth_header(Schema, Signature, PublicKey) ->
    {"Authorization", Schema ++ " "
     ++ PublicKey ++ ":" ++ Signature}.

make_signature_string(#hmac_signature{config = Config,
                                      contentmd5 = ContentMD5, contenttype = ContentType,
                                      date = Date, headers = Headers,
                                      method = Method, resource = Resource}) ->
    Date1 = get_date(Config, Headers, Date),
    string:to_upper(atom_to_list(Method)) ++ "\n"
        ++ ContentMD5 ++ "\n"
        ++ ContentType ++ "\n"
        ++ Date1 ++ "\n"
        ++ canonicalise_headers(Config, Headers)
        ++ canonicalise_resource(Resource).

sign_data(PrivateKey, #hmac_signature{} = Signature) ->
    Str = make_signature_string(Signature),
    sign_data(PrivateKey, Str);
sign_data(PrivateKey, Str) when is_list(Str) ->
    Sign = xmerl_ucs:to_utf8(Str),
    binary_to_list(base64:encode(crypto:hmac(sha, PrivateKey, Sign))).

canonicalise_headers(_Config, []) -> "\n";
canonicalise_headers(#hmac_config{header_prefix = Prefix}, List) when is_list(List) ->
    hma_util:canonicalise_headers(Prefix, List).

canonicalise_resource("http://"  ++ Rest) -> c_res2(Rest);
canonicalise_resource("https://" ++ Rest) -> c_res2(Rest);
canonicalise_resource(X)                  -> c_res3(X).

c_res2(Rest) ->
    N = string:str(Rest, "/"),
    {_, Tail} = lists:split(N, Rest),
    c_res3("/" ++ Tail).

c_res3(Tail) ->
    URL = case string:str(Tail, "#") of
              0 -> Tail;
              N -> {U, _Anchor} = lists:split(N, Tail),
                   U
          end,
    U3 = case string:str(URL, "?") of
             0  -> URL;
             N2 -> {U2, Q} = lists:split(N2, URL),
                   U2 ++ canonicalise_query(Q)
         end,
    string:to_lower(U3).

canonicalise_query(List) ->
    List1 = string:to_lower(List),
    List2 = string:tokens(List1, "&"),
    string:join(lists:sort(List2), "&").

%% if there's a header date take it and ditch the date
get_date(_Config, [], Date) ->
    Date;
get_date(#hmac_config{date_header = DateHeader} = Config, [{K, _V} | T], Date) ->
    case string:to_lower(K) of
        DateHeader ->
            [];
        _ ->
            get_date(Config, T, Date)
    end.

format(Key) ->
    format2(Key, []).

format2([], Acc)                  -> lists:flatten(lists:reverse(Acc));
format2([A, B, C, D | []], Acc)   -> format2([],   [D, C, B, A | Acc]);
format2([A, B, C, D | Rest], Acc) -> format2(Rest, ["-", D, C, B, A | Acc]).
