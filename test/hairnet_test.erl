-module(hairnet_test).
-include_lib("eunit/include/eunit.hrl").

%%%%%%%%%%%%%%%%%%%%%%%%%
%%% Utility functions %%%
%%%%%%%%%%%%%%%%%%%%%%%%%

%% generate_key should generate a 32-byte binary
generate_key_test() ->
    ?assertEqual(32, byte_size(hairnet:generate_key())).

%% generate_key should generate a 32-byte binary
generate_encoded_key_test() ->
    ?assertEqual(32, byte_size(hairnet:decode_key(hairnet:generate_encoded_key()))).

%% generate_iv should generate a 16-byte binary
generate_iv_test() ->
    ?assertEqual(16, byte_size(hairnet:generate_iv())).

encode_key_test() ->
    Key = <<115, 15, 244, 199, 175, 61, 70, 146,
            62, 142, 212, 81, 238, 129, 60, 135, 247,
            144, 176, 162, 38, 188, 150, 169, 45,
            228, 155, 94, 156, 5, 225, 238>>,
    ?assertEqual(<<"cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=">>,
                 hairnet:encode_key(Key)).

decode_key_test() ->
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    ?assertEqual(<<115, 15, 244, 199, 175, 61, 70, 146,
                   62, 142, 212, 81, 238, 129, 60, 135, 247,
                   144, 176, 162, 38, 188, 150, 169, 45,
                   228, 155, 94, 156, 5, 225, 238>>,
                 hairnet:decode_key(Key)).

%% Convert seconds since the Unixtime Epoch to a 64-bit unsigned big-endian integer.
seconds_to_binary_test() ->
    ?assertEqual(<<0, 0, 0, 0, 29, 192, 158, 176>>,
                 hairnet:seconds_to_binary(499162800)).

%% Convert a 64-bit unsigned big-endian integer to seconds since the Unixtime
%% Epoch.
binary_to_seconds_test() ->
    ?assertEqual(499162800,
                 hairnet:binary_to_seconds(<<0, 0, 0, 0, 29, 192, 158, 176>>)).



%%%%%%%%%%%%%%%%%%%%%%%
%%% Roundtrip Tests %%%
%%%%%%%%%%%%%%%%%%%%%%%

verify_and_decrypt_token_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    Tok = hairnet:generate_token(Msg, Key),
    ?assertEqual({ok, Msg},
                 hairnet:verify_and_decrypt_token(Tok, Key, 10)).

verify_and_decrypt_token_internal_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok = hairnet:generate_token(Msg, IV, Now, Key),
    ?assertEqual({ok, Msg},
                 hairnet:verify_and_decrypt_token(Tok, Key, 10, Now)).

verify_and_decrypt_token_expired_ttl_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok = hairnet:generate_token(Msg, IV, Now, Key),
    ?assertEqual({error, too_old},
                 hairnet:verify_and_decrypt_token(Tok, Key, 10, Now+11)).

verify_and_decrypt_token_too_new_ttl_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok = hairnet:generate_token(Msg, IV, Now, Key),
    ?assertEqual({error, too_new},
                 hairnet:verify_and_decrypt_token(Tok, Key, 10, Now-70)).

verify_and_decrypt_token_ignore_ttl_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok = hairnet:generate_token(Msg, IV, Now, Key),
    ?assertEqual({ok, Msg},
                 hairnet:verify_and_decrypt_token(Tok, Key, infinity, Now-70)).

verify_and_decrypt_token_invalid_version_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok1 = hairnet:generate_token(Msg, IV, Now, Key),
    DecodedToken = hairnet:decode_token(Tok1),
    {_, TS1, IV1, CipherText1, Tag1} = hairnet:unpack(DecodedToken),
    <<_Vsn, Rest/binary>> = hairnet:payload(TS1, IV1, CipherText1, Tag1),
    Tok2 = hairnet:encode_token(<<0, Rest/binary>>),
    ?assertEqual({error, bad_version},
                 hairnet:verify_and_decrypt_token(Tok2, Key, 10, Now)).

%% Replaces the HMAC test for the tag
invalid_incorrect_tag_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok1 = hairnet:generate_token(Msg, IV, Now, Key),
    DecodedToken = hairnet:decode_token(Tok1),
    {_Vsn, TS1, IV1, CipherText1, Tag1} = hairnet:unpack(DecodedToken),
    Size = bit_size(Tag1),
    Tok2 = hairnet:encode_token(hairnet:payload(TS1, IV1, CipherText1, <<0:Size>>)),
    ?assertEqual({error, incorrect_mac},
                 hairnet:verify_and_decrypt_token(Tok2, Key, 10, Now)).

%% Replaces the HMAC test for the payload
invalid_incorrect_ciphertext_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok1 = hairnet:generate_token(Msg, IV, Now, Key),
    DecodedToken = hairnet:decode_token(Tok1),
    {_Vsn, TS1, IV1, CipherText1, Tag1} = hairnet:unpack(DecodedToken),
    Size = bit_size(CipherText1),
    Tok2 = hairnet:encode_token(hairnet:payload(TS1, IV1, <<0:Size>>, Tag1)),
    ?assertEqual({error, incorrect_mac},
                 hairnet:verify_and_decrypt_token(Tok2, Key, 10, Now)).

invalid_base64_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok = hairnet:generate_token(Msg, IV, Now, Key),
    ?assertEqual({error, invalid_base64},
                 hairnet:verify_and_decrypt_token(<<"%%%%%%%",Tok/binary>>, Key, 10, Now)).

invalid_payload_format_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    Now = hairnet:erlang_system_seconds(),
    Tok1 = hairnet:generate_token(Msg, IV, Now, Key),
    DecodedToken = hairnet:decode_token(Tok1),
    {_Vsn, TS1, IV1, CipherText1, Tag1} = hairnet:unpack(DecodedToken),
    Tok2 = hairnet:encode_token(
        << (hairnet:payload(TS1, IV1, CipherText1, Tag1))/binary, "garbage" >>
    ),
    ?assertEqual({error, payload_format},
                 hairnet:verify_and_decrypt_token(Tok2, Key, 10, Now)).


invalid_payload_format_alt_test() ->
    Msg = <<"hello">>,
    Key = "cw_0x689RpI-jtRR7oE8h_eQsKImvJapLeSbXpwF4e4=",
    IV = <<0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15>>,
    B64 = base64url:encode_mime(<<"fakepieceofdata">>),
    ?assertEqual({error, payload_format},
                 hairnet:verify_and_decrypt_token(B64, Key, infinity)).


