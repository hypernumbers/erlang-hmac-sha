-module(hmac_api_lib_tests).

-include("src/hmac_api.hrl").
-include_lib("eunit/include/eunit.hrl").

-author("Hypernumbers Ltd <gordon@hypernumbers.com>").


                                                % taken from Amazon docs
%% http://docs.amazonwebservices.com/AmazonS3/latest/dev/index.html?RESTAuthentication.html
hash_test1(_) ->
    Sig = "DELETE\n\n\n\nx-amz-date:Tue, 27 Mar 2007 21:20:26 +0000\n/johnsmith/photos/puppy.jpg",
    Key = ?privatekey,
    Hash = hmac_api_lib:sign2(Key, Sig),
    Expected = "k3nL7gH3+PadhTEVn5Ip83xlYzk=",
    ?assertEqual(Expected, Hash).

%% taken from Amazon docs
%% http://docs.amazonwebservices.com/AmazonS3/latest/dev/index.html?RESTAuthentication.html
hash_test2(_) ->
    Sig = "GET\n\n\nTue, 27 Mar 2007 19:44:46 +0000\n/johnsmith/?acl",
    Key = "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o",
    Hash = hmac_api_lib:sign2(Key, Sig),
    Expected = "thdUi9VAkzhkniLj96JIrOPGi0g=",
    ?assertEqual(Expected, Hash).

%% taken from Amazon docs
%% http://docs.amazonwebservices.com/AmazonS3/latest/dev/index.html?RESTAuthentication.html
hash_test3(_) ->
    Sig = "GET\n\n\nWed, 28 Mar 2007 01:49:49 +0000\n/dictionary/"
        ++ "fran%C3%A7ais/pr%c3%a9f%c3%a8re",
    Key = "uV3F3YluFJax1cknvbcGwgjvx4QpvB+leU8dUj2o",
    Hash = hmac_api_lib:sign2(Key, Sig),
    Expected = "dxhSBHoI6eVSPcXJqEghlUzZMnY=",
    ?assertEqual(Expected, Hash).

signature_test1(_) ->
    URL = "http://example.com:90/tongs/ya/bas",
    Method = post,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "POST\n\n\nSun, 10 Jul 2011 05:07:19 UTC\n\n/tongs/ya/bas",
    ?assertEqual(Expected, Sig).

signature_test2(_) ->
    URL = "http://example.com:90/tongs/ya/bas",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [{"x-amz-acl", "public-read"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\nx-amz-acl:public-read\n/tongs/ya/bas",
    ?assertEqual(Expected, Sig).

signature_test3(_) ->
    URL = "http://example.com:90/tongs/ya/bas",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [{"x-amz-acl", "public-read"},
               {"yantze", "blast-off"},
               {"x-amz-doobie", "bongwater"},
               {"x-amz-acl", "public-write"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\nx-amz-acl:public-read;public-write\nx-amz-doobie:bongwater\n/tongs/ya/bas",
    ?assertEqual(Expected, Sig).

signature_test4(_) ->
    URL = "http://example.com:90/tongs/ya/bas",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [{"x-amz-acl", "public-read"},
               {"yantze", "blast-off"},
               {"x-amz-doobie  oobie \t boobie ", "bongwater"},
               {"x-amz-acl", "public-write"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\nx-amz-acl:public-read;public-write\nx-amz-doobie oobie boobie:bongwater\n/tongs/ya/bas",
    ?assertEqual(Expected, Sig).

signature_test5(_) ->
    URL = "http://example.com:90/tongs/ya/bas",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [{"x-amz-acl", "public-Read"},
               {"yantze", "Blast-Off"},
               {"x-amz-doobie  Oobie \t boobie ", "bongwater"},
               {"x-amz-acl", "public-write"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\nx-amz-acl:public-Read;public-write\nx-amz-doobie oobie boobie:bongwater\n/tongs/ya/bas",
    ?assertEqual(Expected, Sig).

signature_test6(_) ->
    URL = "http://example.com:90/tongs/ya/bas/?andy&zbish=bash&bosh=burp",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\n\n"
        ++ "/tongs/ya/bas/?andy&bosh=burp&zbish=bash",
    ?assertEqual(Expected, Sig).

signature_test7(_) ->
    URL = "http://exAMPLE.Com:90/tONgs/ya/bas/?ANdy&ZBish=Bash&bOsh=burp",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\nSun, 10 Jul 2011 05:07:19 UTC\n\n"
        ++"/tongs/ya/bas/?andy&bosh=burp&zbish=bash",
    ?assertEqual(Expected, Sig).

signature_test8(_) ->
    URL = "http://exAMPLE.Com:90/tONgs/ya/bas/?ANdy&ZBish=Bash&bOsh=burp",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "",
    Headers = [{"x-aMz-daTe", "Tue, 27 Mar 2007 21:20:26 +0000"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\n\n"
        ++"x-amz-date:Tue, 27 Mar 2007 21:20:26 +0000\n"
        ++"/tongs/ya/bas/?andy&bosh=burp&zbish=bash",
    ?assertEqual(Expected, Sig).

signature_test9(_) ->
    URL = "http://exAMPLE.Com:90/tONgs/ya/bas/?ANdy&ZBish=Bash&bOsh=burp",
    Method = get,
    ContentMD5 = "",
    ContentType = "",
    Date = "Sun, 10 Jul 2011 05:07:19 UTC",
    Headers = [{"x-amz-date", "Tue, 27 Mar 2007 21:20:26 +0000"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:make_signature_string(Signature),
    Expected = "GET\n\n\n\n"
        ++"x-amz-date:Tue, 27 Mar 2007 21:20:26 +0000\n"
        ++"/tongs/ya/bas/?andy&bosh=burp&zbish=bash",
    ?assertEqual(Expected, Sig).

amazon_test1(_) ->
    URL = "http://exAMPLE.Com:90/johnsmith/photos/puppy.jpg",
    Method = delete,
    ContentMD5 = "",
    ContentType = "",
    Date = "",
    Headers = [{"x-amz-date", "Tue, 27 Mar 2007 21:20:26 +0000"}],
    Signature = #hmac_signature{method = Method,
                                contentmd5 = ContentMD5,
                                contenttype = ContentType,
                                date = Date,
                                headers = Headers,
                                resource = URL},
    Sig = hmac_api_lib:sign_data(?privatekey, Signature),
    Expected = "k3nL7gH3+PadhTEVn5Ip83xlYzk=",
    ?assertEqual(Expected, Sig).

unit_test_() ->
    Setup   = fun() -> ok end,
    Cleanup = fun(_) -> ok end,

    Series1 = [
               fun hash_test1/1,
               fun hash_test2/1,
               fun hash_test3/1
              ],

    Series2 = [
               fun signature_test1/1,
               fun signature_test2/1,
               fun signature_test3/1,
               fun signature_test4/1,
               fun signature_test5/1,
               fun signature_test6/1,
               fun signature_test7/1,
               fun signature_test8/1,
               fun signature_test9/1
              ],

    Series3 = [
               fun amazon_test1/1
              ],

    {setup, Setup, Cleanup, [
                             {with, [], Series1},
                             {with, [], Series2},
                             {with, [], Series3}
                            ]}.
