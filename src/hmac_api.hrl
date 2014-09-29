-author("Hypernumbers Ltd <gordon@hypernumbers.com>").


%% Define the configuration for the HMAC encoding.  We default to the amazon
%% headers and Schema
-record(hmac_config, { schema = "HMAC" :: string(),
                       header_prefix = "x-hmac-" :: string(),
                       date_header = "x-hmac-date" :: string()
                     }
       ).

-record(hmac_signature, {config = #hmac_config{} :: #hmac_config{},
                         method :: atom(),
                         contentmd5 = "" :: string(),
                         contenttype = "" :: string(),
                         date :: string(),
                         headers = [],
                         resource = "" :: string()
                        }).
