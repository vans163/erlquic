# erlquic
Google QUIC protocol for Erlang

### Status
Currently parsing the CLHO (client hello) is being done.  
  
Test by calling quic_packet:test().

### Misc useful stuff
Useful information can only be obtained from packet caps and reading the C++ and GO Quic servers.  
The RFCs give you an overview but there is no implementation details.  
  
chromium --user-data-dir=/tmp --no-proxy-server --enable-quic \  
--origin-to-force-quic-on=www.example.org:443 \  
--host-resolver-rules="MAP www.example.org:443 127.0.0.1:1443" https://www.example.org
