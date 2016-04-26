hairnet
=====

A take on [fernet](https://github.com/fernet/fernet-erl) using AES-GCM
([AEAD](https://en.wikipedia.org/wiki/Authenticated_encryption))
rather than fernet's AES-128 in CBC mode + HMAC.

The idea is to take what is now a fairly weak crypto library and bring
it up to a higher standard while maintaining a similar interface.

The objective is to:

> "takes a user-provided message (an arbitrary sequence of
> bytes), a key (256 bits), and the current time, and produces a token, which
> contains the message in a form that can't be read or altered without the key."

In terms of AEAD, the PlainText will be the user-provided message, the key
should be any Erlang binary (please use a different one from the one in
`fernet` if you are upgrading), and the current time is going to be used as
the additional authenticated data (AAD), which can be used by the party
doing decryption to validate for staleness.


## Interface

```erlang
1> Key = hairnet:generate_encoded_key().
<<"BVt1_R20scbTwz9t05PrtE4EFAauMeRKTxbwYmUiafY=">>
2> Token = hairnet:generate_token("hello", Key).
<<"AQAAAABXH4wKw8DqUtDjJxAX3BuEHGP9xke0tfY-73uzVCpa1iT5f1wgAAAABbhBUeFl">>
3> hairnet:verify_and_decrypt_token(Token, Key, infinity).
4> TTL = 10. % 10 Seconds
5> hairnet:verify_and_decrypt_token(Token, Key, TTL).
{error, too_old}
```

### Difference from fernet

- `encode_key/2` is gone, since there is no longer a distinction between
  a signing and an encryption key; the AES-GCM algorithm handles this.
- The format changed since the data size is more variable given the AAD,
  and prefixed lengths are being used to carry the content.
- pkcs7 is no longer needed, and the padding-related errors are no longer
  returnable, since this is all handled by the crypto library.
- block sizes warnings are gone, instead an overall `payload_format`
  error value can be returned.
- Dropped compatibility for pre-18 Erlang/OTP copies

Build
-----

    $ rebar3 compile
