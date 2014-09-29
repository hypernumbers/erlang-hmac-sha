-module(hmac_api_client).

-export([
         signed_req/5,
         signed_req/6,
         fire/0
        ]).

-include("hmac_api.hrl").

signed_req(PublicKey, PrivateKey, Path, Headers, Method, Body) ->
    %% TODO: We should add Content-md5 if it's not there
    Authorization = hmac_api_lib:sign(PrivateKey, PublicKey, Method, Path, Headers),
    ibrowse:send_req(Path, [Authorization|Headers], Method, Body).

signed_req(PublicKey, PrivateKey, Path, Headers, Method) ->

    Authorization = hmac_api_lib:sign(PrivateKey, PublicKey, Method, Path, Headers),

    ibrowse:send_req(Path, [Authorization|Headers], Method).

fire() ->
    {PublicKey, PrivateKey} = hmac_api_lib:get_api_keypair(),
    URL = "http://127.0.0.1:14152",
    %% Dates SHOULD conform to Section 3.3 of RFC2616
    %% the examples from the RFC are:
    %% Sun, 06 Nov 1994 08:49:37 GMT  ; RFC 822, updated by RFC 1123
    %% Sunday, 06-Nov-94 08:49:37 GMT ; RFC 850, obsoleted by RFC 1036
    %% Sun Nov  6 08:49:37 1994       ; ANSI C's asctime() format

    %% Dates can be conveniently generated using dh_date.erl
    %% https://github.com/daleharvey/dh_date
    %% which is largely compatible with
    %% http://uk.php.net/date

    %% You MIGHT find it convenient to insist on times in UTC only
    %% as it reduces the errors caused by summer time and other
    %% conversion issues
    Method = post,
    ContentType = "application/json",
    Headers = [{"content-type", ContentType},
               {"date",         "Sun, 10 Jul 2011 05:07:19"},
               {"accept",       "application/json"}],
    Body = "{'hey': 'ho'}",
    Path = "/",
    HTTPAuthHeader = hmac_api_lib:sign(PrivateKey, PublicKey, Method, Path, Headers),
    httpc:request(Method, {URL ++ Path, [HTTPAuthHeader | Headers],
                           ContentType, Body}, [], []).
