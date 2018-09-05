package erasurecode

import (
	"encoding/binary"
	"fmt"
	"github.com/golang/glog"
	"github.com/perlin-network/noise/crypto"
	"github.com/perlin-network/noise/network"
	"github.com/perlin-network/noise/peer"
	"github.com/pkg/errors"
	"github.com/vivint/infectious"
	"sync"
)

type Plugin struct {
	network.Plugin

	SignaturePolicy crypto.SignaturePolicy
	HashPolicy      crypto.HashPolicy

	MinimumRequiredShards int
	TotalShards           int

	Shards sync.Map
}

func (plugin *Plugin) Receive(ctx *network.PluginContext) error {
	switch msg := ctx.Message().(type) {
	case *Shard:
		fileSignature := string(msg.GetFileSignature())

		if shardPoolInterface, exists := plugin.Shards.LoadOrStore(fileSignature, createShardPool(msg)); exists {
			shardPool := (shardPoolInterface).([]infectious.Share)

			if len(shardPool) < int(msg.MinimumRequiredShards) {
				shardPool = append(shardPool, infectious.Share{
					Data:   msg.GetShardData(),
					Number: int(msg.GetShardNumber()),
				})

				plugin.Shards.Store(fileSignature, shardPool)
			} else if len(shardPool) >= int(msg.MinimumRequiredShards) && len(shardPool) <= int(msg.GetTotalShards()) {
				f, err := infectious.NewFEC(int(msg.MinimumRequiredShards), int(msg.GetTotalShards()))
				if err != nil {
					return err
				}

				decoded, err := f.Decode(nil, shardPool)
				if err != nil {
					return err
				}

				serialized, err := serializeShard(ctx.Sender(), decoded)
				if err != nil {
					return err
				}

				// Confirm file signature is not tampered with after shards are re-assemmbled.
				verified := crypto.Verify(
					plugin.SignaturePolicy,
					plugin.HashPolicy,
					ctx.Client().ID.PublicKey,

					serialized,
					msg.GetFileSignature(),
				)

				if verified {
					plugin.Shards.Delete(fmt.Sprintf("%x", msg.GetFileSignature()))
					glog.Infof("\n\nCompleted Message\n%s\n\n", fmt.Sprintf("%x", decoded))

				} else {
					glog.Infof("Decoded message had an malformed signature ... \n ")
					if len(shardPool) == int(msg.GetTotalShards()) {
						return errors.New("could not put together the message due to corrupted shards")
					}
				}
			} else {
				return errors.New("shard pool is larger than maximum size")
			}
		}
	}

	return nil
}

func NewShardPlugin(signaturePolicy crypto.SignaturePolicy, hashPolicy crypto.HashPolicy, minimumRequiredShards int, totalShards int) *Plugin {
	return &Plugin{
		SignaturePolicy:       signaturePolicy,
		HashPolicy:            hashPolicy,
		MinimumRequiredShards: minimumRequiredShards,
		TotalShards:           totalShards,
	}
}

// ShardAndBroadcast shards a message, and broadcasts it over the network.
func (plugin *Plugin) ShardAndBroadcast(net *network.Network, input []byte) error {
	shards, err := plugin.prepareShards(net, input)
	if err != nil {
		return err
	}

	for _, shard := range *shards {
		net.Broadcast(&shard)
	}
	return nil
}

// prepareShards shards a message into a number of secret shares, and wraps them into an array
// of serialized messages ready to be broadcasted over the network.
func (plugin *Plugin) prepareShards(net *network.Network, input []byte) (*[]Shard, error) {
	var shares []Shard

	if input == nil {
		return nil, errors.New("network: input is null")
	}

	serialized, err := serializeShard(net.ID, input)
	if err != nil {
		return nil, err
	}

	fileSignature, err := net.GetKeys().Sign(
		plugin.SignaturePolicy,
		plugin.HashPolicy,
		serialized,
	)
	if err != nil {
		return nil, err
	}

	shards, err := plugin.shardInput(input)
	if err != nil {
		return nil, err
	}

	for _, shard := range *shards {
		msg := Shard{
			FileSignature:         fileSignature,
			ShardData:             shard.Data,
			ShardNumber:           uint64(shard.Number),
			TotalShards:           uint64(plugin.TotalShards),
			MinimumRequiredShards: uint64(plugin.MinimumRequiredShards),
		}

		shares = append(shares, msg)
	}
	return &shares, nil
}

// shardInput shards a byte array into a number of secret shares.
func (plugin *Plugin) shardInput(input []byte) (*[]infectious.Share, error) {

	// Create a *FEC, which will require required pieces for reconstruction at
	// minimum, and generate total total pieces.

	fec, err := infectious.NewFEC(plugin.MinimumRequiredShards, plugin.TotalShards)
	if err != nil {
		return nil, err
	}

	// Prepare to receive the shares of encoded data.
	shares := make([]infectious.Share, plugin.TotalShards)
	output := func(s infectious.Share) {
		// the memory in s gets reused, so we need to make a deep copy
		shares[s.Number] = s.DeepCopy()
	}

	// the data to encode must be padded to a multiple of required, hence the
	// underscores.
	err = fec.Encode(input, output)
	if err != nil {
		return nil, err
	}
	return &shares, nil
}

// serializeShard appends necessary header information to a shard to be broadcasted
// over the network.
func serializeShard(id peer.ID, contents []byte) ([]byte, error) {
	const uint32Size = 4

	serialized := make([]byte, uint32Size+len(id.Address)+uint32Size+len(id.PublicKey)+len(contents))
	pos := 0

	binary.LittleEndian.PutUint32(serialized[pos:], uint32(len(id.Address)))
	pos += uint32Size

	copy(serialized[pos:], []byte(id.Address))
	pos += len(id.Address)

	binary.LittleEndian.PutUint32(serialized[pos:], uint32(len(id.PublicKey)))
	pos += uint32Size

	copy(serialized[pos:], id.PublicKey)
	pos += len(id.PublicKey)

	copy(serialized[pos:], contents)
	pos += len(contents)

	if pos != len(serialized) {
		return nil, errors.Errorf("length mismatch of serialized output: %d != %d", pos, len(serialized))
	}

	return serialized, nil
}

// createShardPool creates a new shard pool, with an appended initial shard.
func createShardPool(shard *Shard) []infectious.Share {
	var pool []infectious.Share

	pool = append(pool, infectious.Share{
		Data:   shard.GetShardData(),
		Number: int(shard.GetShardNumber()),
	})

	return pool
}
