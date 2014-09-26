-module(hmac_api_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("src/hmac_api.hrl").

setup(MockedModules) ->
    [meck:new(M, [unstick]) || M <- MockedModules].

cleanup(MockedModules) ->
    [ ?assert(meck:validate(M)) || M <- MockedModules],
    [ meck:unload(M) || M <- MockedModules].

wm_test_() ->
    MockedModules = [wrq],
    %% Use one of the AWS examples
    {PublicKey, PrivateKey} = {"0PN5J17HBGZHT7JJ3X82", "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o"},
    URL = "http://exAMPLE.Com:90/johnsmith/photos/puppy.jpg",
    Method = delete,
    ContentMD5 = "",
    ContentType = "",
    Date = "Tue, 27 Mar 2007 21:20:26 +0000",
    Headers = [{"x-amz-date", Date}],

    Authorization = "AWS " ++ PublicKey ++ ":k3nL7gH3+PadhTEVn5Ip83xlYzk=",
    {foreach,
     fun() -> setup(MockedModules),
      meck:expect(wrq, method, fun(req) -> Method end),
      meck:expect(wrq, path, fun(req) -> URL end),
      meck:expect(wrq, req_headers, fun(req) -> Headers end),
      meck:expect(wrq, get_req_header, fun(Name, req) ->
                                               case Name of
                                                   "content-md5" -> ContentMD5;
                                                   "content-type" -> ContentType;
                                                   "date" -> Date;
                                                   "authorization" -> Authorization;
                                                   Else ->
                                                       ?debugVal("Unknown header: " ++ Else),
                                                       ?assert(false)
                                               end
                                       end)

     end,
     fun(_) -> cleanup(MockedModules) end,
     [
        {"validate an authorization header",
         fun() ->
                 Got = hmac_api_server:wm_authenticate(req, hmac_aws:config(), PublicKey, PrivateKey),
                 ?assertEqual(Got, match)
         end
        }
     ]
    }.

