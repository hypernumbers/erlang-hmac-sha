-module(hmac_api_server_tests).

-include_lib("eunit/include/eunit.hrl").
-include("src/hmac_api.hrl").

setup(MockedModules) ->
    [meck:new(M, [unstick]) || M <- MockedModules].

cleanup(MockedModules) ->
    [ ?assert(meck:validate(M)) || M <- MockedModules],
    [ meck:unload(M) || M <- MockedModules].

%% Use one of the AWS examples
-define(PUBLIC_KEY, "0PN5J17HBGZHT7JJ3X82").
-define(PRIVATE_KEY, "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o").

%% private key lookup callback function
private_key(_) ->
    ?PRIVATE_KEY.

wm_test_() ->
    MockedModules = [wrq],
    URL = "http://exAMPLE.Com:90/johnsmith/photos/puppy.jpg",
    Method = delete,
    ContentMD5 = "",
    ContentType = "",
    Date = "Tue, 27 Mar 2007 21:20:26 +0000",
    Headers = mochiweb_headers:from_list([{"x-amz-date", Date}]),

    Authorization = "AWS " ++ ?PUBLIC_KEY ++ ":k3nL7gH3+PadhTEVn5Ip83xlYzk=",
    {foreach,
     fun() -> setup(MockedModules),
      meck:expect(wrq, method, fun(req) -> Method end),
      meck:expect(wrq, path, fun(req) -> URL end),
      meck:expect(wrq, req_headers, fun(req) -> Headers end),
      meck:expect(wrq, get_req_header, fun(Name, req) ->
                                               case Name of
                                                   "Content-MD5" -> ContentMD5;
                                                   "Content-Type" -> ContentType;
                                                   "X-AMZ-Date" -> undefined;
                                                   "Date" -> Date;
                                                   "Authorization" -> Authorization;
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
                 Got = hmac_api_server:wm_authenticate(req, state, fun private_key/1, hmac_aws:config()),
                 ?assertEqual({true, req, state}, Got)
         end
        },
        {"wrong private key",
         fun() ->
                 %% This is not the key we're looking for
                 PrivateKeyFun = fun(_Public) -> "theyarenotthedroidsyouarelookingfor" end,
                 Got = hmac_api_server:wm_authenticate(req, state, PrivateKeyFun, hmac_aws:config()),
                 ?assertEqual({"HMAC", req, state}, Got)
         end
        },
        {"unknown private key",
         fun() ->
                 %% know not a key
                 PrivateKeyFun = fun(_Public) -> undefined end,
                 Got = hmac_api_server:wm_authenticate(req, state, PrivateKeyFun, hmac_aws:config()),
                 ?assertEqual({"HMAC", req, state}, Got)
         end
        }
     ]
    }.

wm_missing_headers_test_() ->
    MockedModules = [wrq],
    URL = "http://exAMPLE.Com:90/johnsmith/photos/puppy.jpg",
    Method = delete,
    ContentMD5 = "",
    ContentType = "",
    Date = "Tue, 27 Mar 2007 21:20:26 +0000",
    Headers = mochiweb_headers:from_list([{"x-amz-date", Date}]),

    Authorization = "AWS " ++ ?PUBLIC_KEY ++ ":k3nL7gH3+PadhTEVn5Ip83xlYzk=",
    {foreach,
     fun() -> setup(MockedModules),
      meck:expect(wrq, method, fun(req) -> Method end),
      meck:expect(wrq, path, fun(req) -> URL end),
      meck:expect(wrq, req_headers, fun(req) -> Headers end)
     end,
     fun(_) -> cleanup(MockedModules) end,
     [
        {"missing both Date headers",
         fun() ->
                 meck:expect(wrq, get_req_header, fun(Name, req) ->
                                                          case Name of
                                                              "Content-MD5" -> ContentMD5;
                                                              "Content-Type" -> ContentType;
                                                              "X-AMZ-Date" -> undefined;
                                                              "Date" -> undefined;
                                                              "Authorization" -> Authorization;
                                                          Else ->
                                                              ?debugVal("Unknown header: " ++ Else),
                                                              ?assert(false)
                                               end
                                       end),
                 Got = hmac_api_server:wm_authenticate(req, state, fun private_key/1, hmac_aws:config()),
                 ?assertEqual({error, <<"Missing Date header">>}, Got)
         end
        },
        {"missing Date headers",
         fun() ->
                 meck:expect(wrq, get_req_header, fun(Name, req) ->
                                                          case Name of
                                                              "Content-MD5" -> ContentMD5;
                                                              "Content-Type" -> ContentType;
                                                              "X-AMZ-Date" -> Date;
                                                              "Date" -> undefined;
                                                              "Authorization" -> Authorization;
                                                          Else ->
                                                              ?debugVal("Unknown header: " ++ Else),
                                                              ?assert(false)
                                               end
                                       end),
                 Got = hmac_api_server:wm_authenticate(req, state, fun private_key/1, hmac_aws:config()),
                 ?assertEqual({true, req, state}, Got)
         end
        },
        {"missing X-AMZ-Date headers",
         fun() ->
                 meck:expect(wrq, get_req_header, fun(Name, req) ->
                                                          case Name of
                                                              "Content-MD5" -> ContentMD5;
                                                              "Content-Type" -> ContentType;
                                                              "X-AMZ-Date" -> undefined;
                                                              "Date" -> Date;
                                                              "Authorization" -> Authorization;
                                                          Else ->
                                                              ?debugVal("Unknown header: " ++ Else),
                                                              ?assert(false)
                                               end
                                       end),
                 Got = hmac_api_server:wm_authenticate(req, state, fun private_key/1, hmac_aws:config()),
                 ?assertEqual({true, req, state}, Got)
         end
        },
        {"missing Authorization header",
         fun() ->
                 meck:expect(wrq, get_req_header, fun(Name, req) ->
                                                          case Name of
                                                              "Content-MD5" -> ContentMD5;
                                                              "Content-Type" -> ContentType;
                                                              "X-AMZ-Date" -> Date;
                                                              "Date" -> Date;
                                                              "Authorization" -> undefined;
                                                          Else ->
                                                              ?debugVal("Unknown header: " ++ Else),
                                                              ?assert(false)
                                               end
                                       end),
                 Got = hmac_api_server:wm_authenticate(req, state, fun private_key/1, hmac_aws:config()),
                 ?assertEqual({error, <<"Missing Authorization header">>}, Got)
         end
        }

     ]
    }.

