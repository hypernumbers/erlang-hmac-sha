-module(hmac_api_server).

-include("hmac_api.hrl").
-include_lib("webmachine/include/wm_reqdata.hrl").

-author("Hypernumbers Ltd <gordon@hypernumbers.com>").

-export([
         wm_authenticate/3,
         wm_authenticate/4
        ]).


-spec wm_authenticate(Req :: #wm_reqdata{},
                      PublicKey ::string(),
                      PrivateKey :: string()) -> match | no_match.
wm_authenticate(Req, PublicKey, PrivateKey) ->
    wm_authenticate(Req, #hmac_config{}, PublicKey, PrivateKey).

-spec wm_authenticate(Req :: #wm_reqdata{},
                      Config :: #hmac_config{},
                      PublicKey ::string(),
                      PrivateKey :: string()) -> match | no_match.
wm_authenticate(Req, Config, PublicKey, PrivateKey) ->
    Method = wrq:method(Req),
    Path = wrq:path(Req),
    Headers = hma_util:normalise(wrq:req_headers(Req)),
    ContentMD5 = wrq:get_req_header("content-md5", Req),
    ContentType = wrq:get_req_header("content-type", Req),
    Date = wrq:get_req_header("date", Req),
    Authorization = wrq:get_req_header("authorization", Req),
    Signature = #hmac_signature{config = Config,
                                method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = Path},
    hmac_api_lib:validate(PrivateKey, PublicKey, Authorization, Signature).

