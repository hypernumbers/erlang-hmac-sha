-module(hmac_api_server).

-include("hmac_api.hrl").
-include_lib("webmachine/include/wm_reqdata.hrl").

-export([
         wm_authenticate/3,
         wm_authenticate/4
        ]).


-spec wm_authenticate(Req :: #wm_reqdata{},
                      State :: any(),
                      PrivateKeyFun :: fun((string()) -> string() | undefined))
 -> {true | string(), #wm_reqdata{}, any()} | {error, binary()}.
wm_authenticate(Req, State, PrivateKeyFun) ->
    wm_authenticate(Req, State, PrivateKeyFun, #hmac_config{}).

-spec wm_authenticate(Req :: #wm_reqdata{},
                      State :: any(),
                      PrivateKeyFun :: fun((string()) -> string() | undefined),
                      Config :: #hmac_config{})
 -> {true | string(), #wm_reqdata{}, any()} | {error, binary()}.
wm_authenticate(Req, State, PrivateKeyFun, Config) ->
    case assert_headers(Config, Req) of
        {error, _Error} = Reason ->
            Reason;
        {Authorization, Date} ->
            Method = wrq:method(Req),
            Path = wrq:path(Req),
            Headers = hma_util:normalise(mochiweb_headers:to_list(wrq:req_headers(Req))),
            ContentMD5 = wrq:get_req_header("Content-MD5", Req),
            ContentType = wrq:get_req_header("Content-Type", Req),

            {_Schema, PublicKey, _Sig} = hmac_api_lib:parse_authorization_header(Authorization),

            case PrivateKeyFun(PublicKey) of
                undefined ->
                    {"HMAC", Req, State};
                PrivateKey ->
                    Signature = #hmac_signature{config = Config,
                                                method = Method,
                                                contentmd5 = ContentMD5,
                                                contenttype = ContentType,
                                                date = Date,
                                                headers = Headers,
                                                resource = Path},
                    case hmac_api_lib:validate(PrivateKey, PublicKey, Authorization, Signature) of
                        match ->
                            {true, Req, State};
                        no_match ->
                            {"HMAC", Req, State}
                    end
            end
    end.

%% Check that all the appropriate headers are present in the Request
%% We require
%% 1. Authorization
%% 2. EITHER Date or #hmac_config{date_header} (normally X-HMAC-Date)
assert_headers(Config, Req) ->
    case wrq:get_req_header("Authorization", Req) of
        undefined ->
            {error, <<"Missing Authorization header">>};
        Auth ->
            case date_header(Config, Req) of
                undefined ->
                    {error, <<"Missing Date header">>};
                Date ->
                    {Auth, Date}
            end
    end.

date_header(#hmac_config{header_prefix = Prefix}, Req) ->
    DateHeader = string:to_upper(Prefix) ++ "Date",
    case wrq:get_req_header(DateHeader, Req) of
        undefined -> wrq:get_req_header("Date", Req);
        Date -> Date
    end.

