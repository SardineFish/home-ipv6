# SLAAC Client for my Home Server

Reference: [HomeServer - 家庭 IPv6 组网](https://www.sardinefish.com/blog/617)

## Usage

Require privilege to listen ICMPv6 Router Advertisement

```shell
$ cargo build --release

$ sudo target/release/home-ipv6 ./config.example.yaml
```