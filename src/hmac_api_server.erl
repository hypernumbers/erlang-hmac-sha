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
 -> {true | string(), #wm_reqdata{}, any()}.
wm_authenticate(Req, State, PrivateKeyFun) ->
    wm_authenticate(Req, State, PrivateKeyFun, #hmac_config{}).

-spec wm_authenticate(Req :: #wm_reqdata{},
                      State :: any(),
                      PrivateKeyFun :: fun((string()) -> string() | undefined),
                      Config :: #hmac_config{})
 -> {true | string(), #wm_reqdata{}, any()}.
wm_authenticate(Req, State, PrivateKeyFun, Config) ->
    Method = wrq:method(Req),
    Path = wrq:path(Req),
    Headers = hma_util:normalise(wrq:req_headers(Req)),
    ContentMD5 = wrq:get_req_header("content-md5", Req),
    ContentType = wrq:get_req_header("content-type", Req),
    Date = wrq:get_req_header("date", Req),
    Authorization = wrq:get_req_header("authorization", Req),
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
    end.

