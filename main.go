package main

import (
	"bufio"
	"encoding/binary"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"test/protobuf"
	"time"

	"github.com/golang/glog"
	"github.com/perlin-network/noise/crypto"
	"github.com/perlin-network/noise/crypto/blake2b"
	"github.com/perlin-network/noise/crypto/ed25519"
	"github.com/perlin-network/noise/peer"

	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/network/discovery"
	"github.com/vivint/infectious"
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

type ShardPlugin struct {
	*network.Plugin
	SignaturePolicy     crypto.SignaturePolicy
	HashPolicy          crypto.HashPolicy
	MinimumNeededShards int
	TotalShards         int
	Shards              sync.Map
}

func (state *ShardPlugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *erasurecode.Shard:
		shardsMemPoolInterface, _ := state.Shards.Load(fmt.Sprintf("%x", msg.GetFileSignature()))
		if shardsMemPoolInterface == nil {
			var shardsMemPool []infectious.Share
			shardsMemPool = append(shardsMemPool, infectious.Share{
				Data:   msg.GetShardData(),
				Number: int(msg.GetShardNumber()),
			})
			state.Shards.Store(fmt.Sprintf("%x", msg.GetFileSignature()), shardsMemPool)
		} else {
			shardsMemPool := (shardsMemPoolInterface).([]infectious.Share)
			if len(shardsMemPool) < int(msg.MinimumNeededShards) {
				shardsMemPool = append(shardsMemPool, infectious.Share{
					Data:   msg.GetShardData(),
					Number: int(msg.GetShardNumber()),
				})
				state.Shards.Delete(fmt.Sprintf("%x", msg.GetFileSignature()))
				state.Shards.Store(fmt.Sprintf("%x", msg.GetFileSignature()), shardsMemPool)
			} else if len(shardsMemPool) >= int(msg.MinimumNeededShards) && len(shardsMemPool) <= int(msg.GetTotalShards()) {
				f, err := infectious.NewFEC(int(msg.GetMinimumNeededShards()), int(msg.GetTotalShards()))
				if err != nil {
					glog.Errorf("%+v", err)
				}
				completeMessage, err := f.Decode(nil, shardsMemPool)
				if err != nil {
					glog.Errorf("%+v", err)
				}
				// confirm complete file signature is not damaged
				verification := crypto.Verify(
					state.SignaturePolicy,
					state.HashPolicy,
					ctx.Client().ID.PublicKey,

					serializeMessage(ctx.Sender(), completeMessage),
					msg.GetFileSignature(),
				)
				if verification {
					state.Shards.Delete(fmt.Sprintf("%x", msg.GetFileSignature()))
					glog.Infof("\n\nCompleted Message\n%s\n\n", fmt.Sprintf("%x", completeMessage))

				} else {
					glog.Infof("Decoded message had an malformed signature ... \n ")
					if len(shardsMemPool) == int(msg.GetTotalShards()) {
						return errors.New("Could not put together the message due to corruption")
					}
				}
			} else {
				return errors.New("Shards mempool is larger than maximum size")
			}
		}
	}

	return nil
}
func NewShardPlugin(signaturePolicy crypto.SignaturePolicy, hashPolicy crypto.HashPolicy, minimumNeededShards int, totalShards int) *ShardPlugin {
	result := new(ShardPlugin)
	result.SignaturePolicy = signaturePolicy
	result.HashPolicy = hashPolicy
	result.MinimumNeededShards = minimumNeededShards
	result.TotalShards = totalShards
	return result
}
func main() {
	// glog defaults to logging to a file, override this flag to log to console for testing
	flag.Set("logtostderr", "true")

	// process other flags
	portFlag := flag.Int("port", 3000, "port to listen to")
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

	shardplugin := NewShardPlugin(
		defaultSignaturePolicy,
		defaultHashPolicy,
		minimumNeededShards,
		totalShards)
	// Register newly created shard plugin.
	builder.AddPlugin(shardplugin)

	net, err := builder.Build()
	if err != nil {
		glog.Fatal(err)
		return
	}
	glog.Infof("\n\nErasure code pluging Loaded\n\nDefault Minimum Number of needed chunks = [ %d ]\nDefault Total Number of chunks = [ %d ]\n", shardplugin.MinimumNeededShards, shardplugin.TotalShards)

	go net.Listen()

	if len(peers) > 0 {
		net.Bootstrap(peers...)
	}

	reader := bufio.NewReader(os.Stdin)
	for {
		input, _ := reader.ReadString('\n')
		// skip blank lines
		if len(strings.TrimSpace(input)) == 0 {
			continue
		}

		glog.Infof("\nMessage Sender\n%s\n\nMessage Byte Slice\n%x\nNumber of bytes = [ %d ] \n", net.Address, []byte(input), len([]byte(input)))

		if len([]byte(input))%shardplugin.MinimumNeededShards != 0 {
			latgestPrimeFactor := largestPrimeFactors(len([]byte(input)))
			shardplugin.MinimumNeededShards = latgestPrimeFactor
			shardplugin.TotalShards = shardplugin.TotalShards + shardplugin.MinimumNeededShards
			glog.Infof("\n\nRevised Minimum Number of needed chunks = [ %d ]\nRevised Total Number of chunks = [ %d ]\n", shardplugin.MinimumNeededShards, shardplugin.TotalShards)

		}
		err = shardplugin.ShardAndBroadcast(net, []byte(input))
		if err != nil {
			glog.Fatal(err)
			return
		}

	}

}
func (shardplugin *ShardPlugin) ShardAndBroadcast(net *network.Network, input []byte) error {
	shards, err := shardplugin.prepareShards(net, input)
	if err != nil {
		return (err)
	}
	for _, shard := range *shards {
		net.Broadcast(&shard)
	}
	return nil
}
func (shardplugin *ShardPlugin) prepareShards(net *network.Network, input []byte) (*[]erasurecode.Shard, error) {

	var result []erasurecode.Shard

	if input == nil {
		return nil, errors.New("network: input is null")
	}

	fileSignature, err := net.GetKeys().Sign(
		shardplugin.SignaturePolicy,
		shardplugin.HashPolicy,
		serializeMessage(net.ID, input),
	)
	inputShards, err := shardplugin.shardInput(input)
	if err != nil {
		return nil, err
	}
	for _, inputShard := range *inputShards {

		msg := erasurecode.Shard{
			FileSignature:       fileSignature,
			ShardData:           inputShard.Data,
			ShardNumber:         uint64(inputShard.Number),
			TotalShards:         uint64(shardplugin.TotalShards),
			MinimumNeededShards: uint64(shardplugin.MinimumNeededShards),
		}

		result = append(result, msg)
	}
	return &result, nil
}

func (shardplugin *ShardPlugin) shardInput(input []byte) (*[]infectious.Share, error) {

	// Create a *FEC, which will require required pieces for reconstruction at
	// minimum, and generate total total pieces.

	f, err := infectious.NewFEC(shardplugin.MinimumNeededShards, shardplugin.TotalShards)
	if err != nil {
		return nil, err
	}

	// Prepare to receive the shares of encoded data.
	shares := make([]infectious.Share, shardplugin.TotalShards)
	output := func(s infectious.Share) {
		// the memory in s gets reused, so we need to make a deep copy
		shares[s.Number] = s.DeepCopy()
	}

	// the data to encode must be padded to a multiple of required, hence the
	// underscores.
	err = f.Encode((input), output)
	if err != nil {
		return nil, err
	}
	return &shares, nil
}
func serialiseShard(id peer.ID, input infectious.Share) []byte {
	var result []byte
	result = append(result, input.Data...)
	result = append(result, ([]byte(strconv.Itoa(input.Number)))...)
	result = serializeMessage(id, result)

	return result
}
func serializeMessage(id peer.ID, message []byte) []byte {
	const uint32Size = 4

	serialized := make([]byte, uint32Size+len(id.Address)+uint32Size+len(id.Id)+len(message))
	pos := 0

	binary.LittleEndian.PutUint32(serialized[pos:], uint32(len(id.Address)))
	pos += uint32Size

	copy(serialized[pos:], []byte(id.Address))
	pos += len(id.Address)

	binary.LittleEndian.PutUint32(serialized[pos:], uint32(len(id.Id)))
	pos += uint32Size

	copy(serialized[pos:], id.Id)
	pos += len(id.Id)

	copy(serialized[pos:], message)
	pos += len(message)

	if pos != len(serialized) {
		panic("internal error: invalid serialization output")
	}

	return serialized
}
func largestPrimeFactors(n int) int {
	var primes []int
	result := -1

	// Get the number of 2s that divide n
	for n%2 == 0 {
		primes = append(primes, 2)
		n = n / 2
	}

	// n must be odd at this point. so we can skip one element
	// (note i = i + 2)
	for i := 3; i*i <= n; i = i + 2 {
		// while i divides n, append i and divide n
		for n%i == 0 {
			primes = append(primes, i)
			n = n / i
		}
	}

	// This condition is to handle the case when n is a prime number
	// greater than 2
	if n > 2 {
		primes = append(primes, n)
	}
	for _, e := range primes {
		if e >= result {
			result = e
		}
	}

	return result
}
