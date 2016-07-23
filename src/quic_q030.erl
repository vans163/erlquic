-module(quic_q030).

-compile(export_all).

-include("global.hrl").

handshake(Bin) ->
    #{payload:= Payload} = parse(Bin),
    #{tags:= Tags=#{tag:= <<"CHLO">>}} = Payload,

    %Check what this is for later
    SCID = maps:get(<<"SCID">>, Tags, undefined),
    case SCID of
        undefined -> pass
    end,
    STK = maps:get(<<"STK">>, Tags, undefined),
    case STK of
        undefined -> pass
    end,

    SNIHost = maps:get(<<"SNI">>, Tags),

    MsgToSign = <<"QUIC server config signature", 0, "SCFG">>,
    Proof = public_key:sign(MsgToSign, sha256, private_key_dsa),

    CommonCertificateSetsHashes = maps:get(<<"CCS">>, Tags),
    CachedCertsHashes = maps:get(<<"CCRT">>, Tags),

    Token = <<"token 127.0.0.1">>
    .

%reset frame
parse(<<_:6, 1:1, _:1, CID:64/little, "PRST", R/binary>>) ->
    exit(reset_todo)
;

%frame  SeqLen0 SIDLen 3 Ver 1
parse(<<_:2, 0:2, 3:2, 0:1, 1:1, CID:64/little, Ver:4/binary, Seq:8, R/binary>>) ->
    PayloadMap = parse_payload(R),
    #{cid=> CID, seq=> Seq, payload=> PayloadMap}
;


%frame  SeqLen0 SIDLen 3 Ver 0
parse(<<_:2, 0:2, 3:2, 0:1, 0:1, CID:64/little, Seq:8, R/binary>>) ->
    exit(to_do)
;

%frame  SeqLen0 SIDLen 0 Ver 0
parse(<<_:2, 0:2, 3:2, 0:1, 0:1, Seq:8, R/binary>>) ->
    exit(to_do)
.

%STREAM frame
parse_payload(<<Hash:96/little, 
    _:5, 0:1, 0:1, Entropy: 1, %private flags no FEC support
    1:1, 0:1, DataLenBit:1, OffsetLen:3, StreamLen:2,
    R/binary>>) ->
    {StreamID, R1} = parse_stream_id(StreamLen, R),
    {DataLen, R2} = parse_data_len(DataLenBit, R1),
    Tags = quic_tag_value_map:parse(R2),

    #{hash=>Hash, streamid=> StreamID, tags=> Tags}
    .

parse_stream_id(0, <<SID:8, Rest/binary>>) -> {SID, Rest};
parse_stream_id(1, <<SID:16/little, Rest/binary>>) -> {SID, Rest};
parse_stream_id(2, <<SID:24/little, Rest/binary>>) -> {SID, Rest};
parse_stream_id(3, <<SID:32/little, Rest/binary>>) -> {SID, Rest}.

parse_data_len(0, <<Rest/binary>>) -> {exit(data_len_0_todo), Rest};
parse_data_len(1, <<DataLen:16/little, Rest/binary>>) -> {DataLen, Rest}.