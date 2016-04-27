%%% @author Fred Hebert <mononcqc@ferd.ca>
%%% @copyright (C) 2016, Heroku
%%% @doc
%%%
%%% Implements fernet-equivalent token generation and verification,
%%% but using the safer AES-GCM AEAD crypto.
%%%
%%% @end
-module(hairnet).

%% API exports
-export([generate_key/0, generate_encoded_key/0,
         encode_key/1, decode_key/1,
         generate_token/2, verify_and_decrypt_token/3]).

-ifdef(TEST).
-compile(export_all).
-endif.

%%====================================================================
%% API functions
%%====================================================================
-define(VERSION, 1).
-define(TAG_SIZE, 16). % 128 bits
-define(IV_BYTES, 16). % 128 bits
-define(TS_BYTES, 8).  % 64 bits
-define(PL_BYTES, 1).  % 8 bits
-define(MAX_32, 4294967295).
-define(MAX_64, 18446744073709551615).
-define(MAX_SKEW, 60).

-type key() :: <<_:256>>.
-type encoded_key() :: binary().
-type encoded_token() :: binary().

%% @doc Generate a pseudorandom 256 bits / 32 bytes key.
-spec generate_key() -> key().
generate_key() ->
    crypto:strong_rand_bytes(32).

%% @doc Generate a pseudorandom 32 bytes key, and encode it with the
%% proper base64url format for interoperability.
-spec generate_encoded_key() -> encoded_key().
generate_encoded_key() ->
    base64url:encode_mime(crypto:strong_rand_bytes(32)).

%% @doc Encode a key using base64url encoding format for interoperability
-spec encode_key(key()) -> encoded_key().
encode_key(<<Key:32/binary>>) ->
    base64url:encode_mime(Key).

%% @doc Decode a base64url encoded key.
-spec decode_key(encoded_key()) -> key().
decode_key(Key) ->
    base64url:decode(Key).

%% @doc Generate a token (encrypt + sign) for the provided `Message'
%% using the supplied `Key'.
-spec generate_token(iodata(), encoded_key()) -> encoded_token().
generate_token(Message, Key) ->
    generate_token(Message, generate_iv(), erlang_system_seconds(), Key).

%% @doc Verify a token and extract the message
-spec verify_and_decrypt_token(encoded_token(), encoded_key(), TTL::integer() | infinity) ->
    {ok, binary()} | {error, atom()}.
verify_and_decrypt_token(Token, Key, infinity) ->
    verify_and_decrypt_token(Token, Key, infinity, undefined);
verify_and_decrypt_token(Token, Key, TTL) ->
    verify_and_decrypt_token(Token, Key, TTL, erlang_system_seconds()).

%%====================================================================
%% Internal functions
%%====================================================================

%% @private Encrypts all of the data. The `Seconds' value is encoded to
%% a 64 bits unsigned in a binary (in network order) and used as the AAD,
%% similarly to how it was part of the HMAC in fernet.
-spec generate_token(iodata(), <<_:128>>, integer(), key()) -> binary().
generate_token(Message, IV, Seconds, EncodedKey) ->
    EncodedSeconds = seconds_to_binary(Seconds),
    Key = decode_key(EncodedKey),
    {CipherText, Tag} = block_encrypt(Key, IV, Message, EncodedSeconds),
    encode_token(payload(EncodedSeconds, IV, CipherText, Tag)).

%% @private Decode all of the data.
verify_and_decrypt_token(EncodedToken, EncodedKey, TTL, Now) ->
    try
        DecodedToken = decode_token(EncodedToken),
        {Vsn, TS, IV, CipherText, Tag} = unpack(DecodedToken),
        Key = decode_key(EncodedKey),
        validate_vsn(Vsn),
        validate_ttl(Now, binary_to_seconds(TS), TTL),
        block_decrypt(Key, IV, Tag, CipherText, TS)
    of
        error ->
            {error, incorrect_mac};
        Decrypted ->
            {ok, Decrypted}
    catch
        throw:payload_format = Err -> {error, Err};
        throw:invalid_base64 = Err -> {error, Err};
        throw:bad_version = Err -> {error, Err};
        throw:too_old = Err -> {error, Err};
        throw:too_new = Err -> {error, Err}
    end.

%% @private Properly, an IV should never be reused with the same key twice
%% since that would leak information. GCM mode allows to use counters
%% in here, which allows for easy parallelisation, but in this here
%% case, we'll stick to the strong rand bytes crypto primitives so that
%% the library is generally stateless.
-spec generate_iv() -> <<_:128>>.
generate_iv() ->
    crypto:strong_rand_bytes(16).

block_encrypt(Key, IV, Message, EncodedSeconds) ->
    crypto:block_encrypt(aes_gcm, Key, IV, {EncodedSeconds, Message}).

block_decrypt(Key, IV, Tag, Message, EncodedSeconds) ->
    crypto:block_decrypt(aes_gcm, Key, IV, {EncodedSeconds, Message, Tag}).

%% @private Encode the given payload. For the sake of simplicity, we only
%% care for lengths for payloads and tags that fit within 32 bits or
%% 64 bits integers for representation; hopefully much shorter.
payload(EncodedSeconds, IV, CipherText, Tag) ->
    16 = erlang:iolist_size(Tag), % assertions!
    <<?VERSION, EncodedSeconds/binary, IV/binary, Tag/binary, CipherText/binary>>.

unpack(<<Vsn:1/binary, TS:?TS_BYTES/binary, IV:?IV_BYTES/binary,
         Tag:?TAG_SIZE/binary, CipherText/binary>>) ->
    {Vsn, TS, IV, CipherText, Tag};
unpack(_) ->
    throw(payload_format).

encode_token(Token) ->
    base64url:encode_mime(Token).

decode_token(EncodedToken) ->
    try
        base64url:decode(EncodedToken)
    catch
        error:{badarg, _Char} -> throw(invalid_base64)
    end.

%%-------------------------------------------------------------------
%% Validation Helpers
%%-------------------------------------------------------------------
validate_vsn(<<?VERSION>>) -> ok;
validate_vsn(_) -> throw(bad_version).

validate_ttl(_, _, infinity) ->
    ok;
validate_ttl(Now, TS, TTL) ->
   Diff = Now - TS,
   AbsDiff = abs(Diff),
   if Diff < 0, AbsDiff < ?MAX_SKEW -> ok; % in the past but within skew
      Diff < 0 -> throw(too_new); % in the past, with way too large of a  skew
      Diff >= 0, Diff < TTL -> ok; % absolutely okay
     %Diff > 0, Diff > TTL, Diff-TTL < ?MAX_SKEW -> ok; % past the TTL, but within skew
      Diff > 0, Diff > TTL -> throw(too_old) % according to spec, skew doesn't apply here
   end.

%%-------------------------------------------------------------------
%% Time Helpers
%%-------------------------------------------------------------------
-spec seconds_to_binary(integer()) -> binary().
seconds_to_binary(Seconds) ->
    <<Seconds:64/big-unsigned>>.

-spec binary_to_seconds(binary()) -> integer().
binary_to_seconds(<<Bin:64>>) ->
    Bin.

-spec erlang_system_seconds() -> integer().
erlang_system_seconds() ->
    erlang:system_time(seconds).
