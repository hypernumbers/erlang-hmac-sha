-author("Hypernumbers Ltd <gordon@hypernumbers.com>").


%% Define the configuration for the HMAC encoding.  We default to the amazon
%% headers and Schema
-record(hmac_config, { schema = "HMAC" :: string(),
                       header_prefix = "x-hmac-" :: string(),
                       date_header = "x-hmac-date" :: string()
                     }
       ).

%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%%                                                                          %%%
%%% Default values for defining a generic API                                %%%
%%%                                                                          %%%
%%% Only change these if you alter the canonicalisation                      %%%
%%%                                                                          %%%
%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%%
%%-define(schema, "MOCHIAPI").
%%-define(headerprefix, "x-mochiapi-").
%%-define(dateheader, "x-mochiapi-date").


-record(hmac_signature, {config = #hmac_config{} :: #hmac_config{},
                         method,
                         contentmd5,
                         contenttype,
                         date,
                         headers,
                         resource
                        }).
