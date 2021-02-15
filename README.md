This script is ad-hoc solution for inspecting **MQTT over TLS** traffic. 

This is a continuation of work started in [mitmproxy-mqtt-script](https://github.com/nikitastupin/mitmproxy-mqtt-script).
This fork supports (almost) all MQTT packet types, multiple packets handling, and more.

## Usage

Run mitmproxy as `mitmproxy --mode transparent --tcp-hosts '.*' -s plugin.py`. Messages will be displayed at the event
log (press `shift + e`).

Of course before that you have to prepare a target device and your host running mitmproxy:
* Install mitmproxy's root certificate on a target device.
* Route device's traffic to mitmproxy. See https://docs.mitmproxy.org/stable/ for the details.
* https://docs.mitmproxy.org/stable/howto-transparent/.

If server requires x509 client authentication `--set client_certs=cert.pem` mitmproxy's option might be useful.

## Roadmap

- [ ] [Add support for non-HTTP flows to the UI](https://github.com/mitmproxy/mitmproxy/issues/1020).
- [x] Implement parsing of `PUBREC`, `PUBREL` and `PUBCOMP` MQTT packet types.
- [ ] Add support for MQTT to mitmproxy including interception, modification and replay.

## Credits

* https://github.com/mitmproxy/mitmproxy/blob/master/examples/complex/tcp_message_buffer.py
* https://github.com/eclipse/paho.mqtt.python/blob/master/src/paho/mqtt/client.py
