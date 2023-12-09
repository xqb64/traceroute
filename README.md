![traceroute](traceroute.png)

<h1 align="center">
traceroute
</h1>

A traceroute(1) implementation written in Rust.

## How it works

**traceroute** starts by slicing the `(1..=hops)` range of TTL (Time-to-Live) values into batches of size 4 (currently hard-coded), and for each value in a batch, it rapidly sends `probes` probes that share the TTL value. Then, it enters a loop and uses `tokio::select!` to concurrently wait for the responses to the probes or the probes timing out. When there are no more outstanding probes (tracked by a `VecDeque` internally), it goes to the next batch and repeats this process. 

The TTL starts at 1 and increments subsequently. As these probes traverse the network, each router they encounter reduces the TTL by one before forwarding them onward. When the TTL of a probe reaches zero, the router in question responds with an ICMP (Internet Control Message Protocol) Time Exceeded message, indicating the path that the probe has taken.

The procedure continues until the probes receive either a Destination Unreachable or an Echo Reply message. These responses signify that the probes have successfully reached the final destination, marking the completion of the route tracing process.

## Design notes

### The benefits of not doing it sequentially

For instance, consider a scenario with a 10-hop route where there's a 30-second delay, possibly due to network latency or router processing time, at hop 6.

In a sequential approach, where each hop is processed one after the other, the total delay encountered would be cumulative. This means for a 30-second delay at hop 6, the total wait time would be `5 * 30s + t` (where `t` is the time taken for the first 5 hops), which could amount to over 150 seconds plus the time for the initial hops.

However, with this approach, we can send out probes concurrently, meaning that all probes will encounter the delay simultaneously. As a result, the effective wait time due to the delay is just 30 seconds.

## Compiling

```
git clone https://github.com/xqb64/traceroute
cd traceroute
cargo build --release
```

This program requires `cap_net_raw`, so make sure you set that on the binary:

```
sudo setcap cap_net_raw+eip target/release/traceroute
```

## Tests

There is no test suite as of now, except for the `raw-socket` crate which is vendored.

## Usage

```
traceroute 0.1.0

USAGE:
    traceroute [OPTIONS] <target>

FLAGS:
        --help       Prints help information
    -V, --version    Prints version information

OPTIONS:
    -h, --hops <hops>             [default: 30]
    -P, --probes <probes>         [default: 3]
    -p, --protocol <protocol>     [default: udp]
    -t, --timeout <timeout>       [default: 3]

ARGS:
    <target>
```

## Contributing

Contributors to this project are very welcome. Fork the repository and submit a PR.

There is a pre-commit hook in the hook folder that could be helpful during development.

## Licensing

Licensed under the [MIT License](https://opensource.org/licenses/MIT). For details, see [LICENSE](https://github.com/xqb64/traceroute/blob/master/LICENSE).
