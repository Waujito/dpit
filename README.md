# DPIT

What may be better way to understand the technology than write it? Yeah, in this project I try to create my own Deep Packet Inspection tool. My goal is to create the tool that is impossible to hack with internet traffic obfuscation. Basically, this is a conntrack utility with smart traffic logging in the map. 

Currently, dpit may be used only for TLS traffic filtering.

Moreover, this project is written in the eBPF, the progressive secure kernel-space technology. Yeah, thats too much pain, I know :)

Requires kernel version >= 5.17 (bpf_loop)

You can observe the logs of eBPF program with

```
sudo cat /sys/kernel/debug/tracing/trace_pipe
```

Note, that this command produces the logs in real time, you don't want to restart it each time for update.

The project has support for logging to PostgreSQL. It logs every single connection to any server with TLS. Not only dropped domains, but all. 

Also throttling is implemented if we just want to slow-down the resource connection. The throttling is implemented in bidirectional manner, meaning both server and client traffic will be throttling. The throttling is implemented as random drop of client-server TCP packets.
