-module(hmac_api_server).

-include("hmac_api.hrl").

-author("Hypernumbers Ltd <gordon@hypernumbers.com>").

-export([
         cowboy_authorize_request/3,
         mochi_authorize_request/3
        ]).

cowboy_authorize_request(Req, PublicKey, PrivateKey) ->
    {Method, _}  = cowboy_req:method(Req),
    Method2      = list_to_existing_atom(binary_to_list(Method)),
    {Path, _}    = cowboy_req:path(Req),
    Path2        = binary_to_list(Path),
    {Headers, _} = cowboy_req:headers(Req),
    Headers2     = [{binary_to_list(K), binary_to_list(V)}
                    || {K, V} <- Headers],
    Headers3     = hma_util:normalise(Headers2),
    ContentMD5   = hma_util:get_header(Headers3, "content-md5"),
    ContentType  = hma_util:get_header(Headers3, "content-type"),
    Date         = hma_util:get_header(Headers3, "date"),
    IncAuth      = hma_util:get_header(Headers3, "authorization"),
    Signature = #hmac_signature{method      = Method2,
                                contentmd5  = ContentMD5,
                                contenttype = ContentType,
                                date        = Date,
                                headers     = Headers3,
                                resource    = Path2},
    hmac_api_lib:validate(PrivateKey, PublicKey, IncAuth, Signature).

-spec mochi_authorize_request(_Req,
                              PublicKey ::string(),
                              PrivateKey :: string()) -> match | no_match.
mochi_authorize_request(Req, PublicKey, PrivateKey) ->
    Method      = Req:get(method),
    Path        = Req:get(path),
    Headers     = hma_util:normalise(mochiweb_headers:to_list(Req:get(headers))),
    ContentMD5  = hma_util:get_header(Headers, "content-md5"),
    ContentType = hma_util:get_header(Headers, "content-type"),
    Date        = hma_util:get_header(Headers, "date"),
    IncAuth     = hma_util:get_header(Headers, "authorization"),
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = Path},
    hmac_api_lib:validate(PrivateKey, PublicKey, IncAuth, Signature).

%%
%% Helper functions
%%
