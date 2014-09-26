-module(hmac_aws).

-export([
         config/0
        ]).

-include("hmac_api.hrl").

-spec config() -> #hmac_config{}.
config() ->
    #hmac_config{schema = "AWS",
                 header_prefix = "x-amz-",
                 date_header = "x-amz-date"
                }.
