![traceroute](traceroute.png)

<h1 align="center">
traceroute
</h1>

An asynchronous traceroute(1) implementation written in Rust.

## How it works

traceroute spawns a maximum of 255 concurrent tokio tasks, regulated by a semaphore to control the number of active tasks at any given time (so that we do not end up sending out more probes than needed). Each task is responsible for dispatching three individual probes towards a specified target host. These probes share an identical Time-to-Live (TTL) value, which starts at 1 and increments subsequently.

As these probes traverse the network, each router they encounter reduces the TTL by one before forwarding them onward. When the TTL of a probe reaches zero, the router in question responds with an ICMP (Internet Control Message Protocol) Time Exceeded message, indicating the path that the probe has taken.

The procedure continues until the probes receive either a Destination Unreachable or an Echo Reply message. These responses signify that the probes have successfully reached the final destination, marking the completion of the route tracing process.

## Why is it async

For instance, consider a scenario with a 10-hop route where there's a 30-second delay, possibly due to network latency or router processing time, at hop 6.

In a sequential approach, where each hop is processed one after the other, the total delay encountered would be cumulative. This means for a 30-second delay at hop 6, the total wait time would be `5 * 30s + t` (where `t` is the time taken for the first 5 hops), which could amount to over 150 seconds plus the time for the initial hops.

However, with an async approach, we can send out probes to all hops concurrently, meaning that all probes will encounter the delay simultaneously. As a result, the effective wait time due to the delay is just 30 seconds.

## Notes

The `raw-socket` crate is vendored.