//go:generate protoc -I. --gogofast_out=. erasurecode/shard.proto

package main

import (
	"bufio"
	"flag"
	"os"
	"strings"
	"time"

	"github.com/damoonazarpazhooh/noise-erasurecode-plugin/erasurecode"
	"github.com/golang/glog"
	"github.com/perlin-network/noise/crypto/blake2b"
	"github.com/perlin-network/noise/crypto/ed25519"
	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/network/discovery"
)

const (
	defaultConnectionTimeout = 60 * time.Second
	defaultReceiveWindowSize = 4096
	defaultSendWindowSize    = 4096
	defaultWriteBufferSize   = 4096
	defaultWriteFlushLatency = 50 * time.Millisecond
	defaultWriteTimeout      = 3 * time.Second
	totalShards              = 6
	minimumNeededShards      = 4
)

var (
	defaultSignaturePolicy = ed25519.New()
	defaultHashPolicy      = blake2b.New()
)

func main() {
	// glog defaults to logging to a file, override this flag to log to console for testing
	flag.Set("logtostderr", "true")

	// process other flags
	portFlag := flag.Int("port", 9999, "port to listen to")
	hostFlag := flag.String("host", "localhost", "host to listen to")
	protocolFlag := flag.String("protocol", "tcp", "protocol to use (kcp/tcp)")
	peersFlag := flag.String("peers", "", "peers to connect to")
	flag.Parse()

	port := uint16(*portFlag)
	host := *hostFlag
	protocol := *protocolFlag
	peers := strings.Split(*peersFlag, ",")

	keys := ed25519.RandomKeyPair()

	glog.Infof("Private Key: %s", keys.PrivateKeyHex())
	glog.Infof("Public Key: %s", keys.PublicKeyHex())

	builder := network.NewBuilderWithOptions(
		network.ConnectionTimeout(defaultConnectionTimeout),
		network.SignaturePolicy(defaultSignaturePolicy),
		network.HashPolicy(defaultHashPolicy),
		network.RecvWindowSize(defaultReceiveWindowSize),
		network.SendWindowSize(defaultSendWindowSize),
		network.WriteBufferSize(defaultWriteBufferSize),
		network.WriteFlushLatency(defaultWriteFlushLatency),
		network.WriteTimeout(defaultWriteTimeout),
	)
	builder.SetKeys(keys)
	builder.SetAddress(network.FormatAddress(protocol, host, port))

	// Register peer discovery plugin.
	builder.AddPlugin(new(discovery.Plugin))

	// Create a new instance of shard plugin.
	plugin := erasurecode.NewShardPlugin(
		defaultSignaturePolicy,
		defaultHashPolicy,
		minimumNeededShards,
		totalShards)

	// Register newly created shard plugin.
	builder.AddPlugin(plugin)

	net, err := builder.Build()
	if err != nil {
		glog.Fatal(err)
		return
	}
	glog.Infof("\n\nErasure code pluging Loaded\n\nDefault Minimum Number of needed chunks = [ %d ]\nDefault Total Number of chunks = [ %d ]\n", plugin.MinimumRequiredShards, plugin.TotalShards)

	go net.Listen()

	if len(peers) > 0 {
		net.Bootstrap(peers...)
	}

	reader := bufio.NewReader(os.Stdin)

	for {
		input, _ := reader.ReadString('\n')

		// Skip blank lines.
		if len(strings.TrimSpace(input)) == 0 {
			continue
		}

		glog.Infof("\nMessage Sender\n%s\n\nMessage Byte Slice\n%x\nNumber of bytes = [ %d ] \n", net.Address, []byte(input), len([]byte(input)))

		// Optional: we optimize the minimum required shards and total shards w.r.t. the input
		// by setting the minimum required shards to be the largest prime factor of the size
		// of the input.
		//
		// The default minimum required/total required shards otherwise may be specified upon
		// the instantiation of erasurecode.Plugin.
		if len([]byte(input))%plugin.MinimumRequiredShards != 0 {
			largestPrimeFactor := largestPrimeFactor(len([]byte(input)))

			plugin.MinimumRequiredShards = largestPrimeFactor
			plugin.TotalShards = plugin.TotalShards + plugin.MinimumRequiredShards

			glog.Infof("\n\nRevised Minimum Number of needed chunks = [ %d ]\nRevised Total Number of chunks = [ %d ]\n", plugin.MinimumRequiredShards, plugin.TotalShards)

		}

		err := plugin.ShardAndBroadcast(net, []byte(input))
		if err != nil {
			glog.Fatal(err)
		}
	}
}

// largestPrimeFactor returns the largest prime factor of a provided integer.
func largestPrimeFactor(a int) int {
	var primes []int
	result := -1

	// Get the number of 2s that divides `a`
	for a%2 == 0 {
		primes = append(primes, 2)
		a = a / 2
	}

	// `a` must be odd at this point. so we can skip one element
	// (note i = i + 2)
	for i := 3; i*i <= a; i = i + 2 {
		// while i divides a, append i and divide a
		for a%i == 0 {
			primes = append(primes, i)
			a = a / i
		}
	}

	// This condition is to handle the case when a is a prime number
	// greater than 2
	if a > 2 {
		primes = append(primes, a)
	}

	for _, e := range primes {
		if e >= result {
			result = e
		}
	}

	return result
}
