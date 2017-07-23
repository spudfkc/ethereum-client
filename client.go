package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	ethcrypto "github.com/ethereum/go-ethereum/crypto"
	"crypto/ecdsa"
	"github.com/ethereum/go-ethereum/rlp"
	"io/ioutil"
	"math/big"
	"net"
	"sync"
	"time"
	"crypto/elliptic"
	"crypto/rand"
)

const (
	PINGNODE_PACKET_TYPE byte = 1
	PINGNODE_VERSION     byte = 3
)

type EthPacket interface {
	Pack() []byte
	GetPacketType() byte
	GetVersion() byte
}

type EndPoint struct {
	Ip      net.IP
	UdpPort uint16
	TcpPort uint16
}

type PingPacket struct {
	ToEndPoint   EndPoint
	FromEndPoint EndPoint
}

func addressToBytes(ip net.IP) []byte {
	// TODO this only supports IPv4
	result := big.NewInt(0)
	result.SetBytes(ip)
	return result.Bytes()
}

func (pingNode PingPacket) GetVersion() byte {
	return PINGNODE_VERSION
}

func (pingNode PingPacket) GetPacketType() byte {
	return PINGNODE_PACKET_TYPE
}

func (pingNode PingPacket) Pack() []byte {
	var result []byte

	result = append(result, pingNode.GetVersion())
	result = append(result, pingNode.FromEndPoint.Pack()...)
	result = append(result, pingNode.ToEndPoint.Pack()...)

	b := make([]byte, 4)
	duration, _ := time.ParseDuration("60s")
	t := time.Now().Add(duration).Unix()
	binary.BigEndian.PutUint32(b, uint32(t))
	result = append(result)

	return result
}

func (pingNode PingPacket) DecodeRLP(stream *rlp.Stream) error {
	b, err := stream.Raw()
	if err != nil {
		panic(fmt.Sprintf("failed to get bytes from stream: %v", err))
	}
	fmt.Printf("GOT STREAM BYTES: %v\n", b)

	return nil
}

// TODO I think this can be refactored and not have as much unnecessary work
func (endpoint *EndPoint) Pack() []byte {
	var result []byte

	addrBuf := make([]byte, 4)
	addrBytes := big.NewInt(0)

	addrBytes.SetBytes(endpoint.Ip.To4())
	binary.BigEndian.PutUint32(addrBuf, uint32(addrBytes.Uint64()))
	result = append(result, addrBytes.Bytes()...)

	udpBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(udpBytes, endpoint.UdpPort)
	result = append(result, udpBytes...)

	tcpBytes := make([]byte, 4)
	binary.BigEndian.PutUint16(tcpBytes, endpoint.TcpPort)
	result = append(result, tcpBytes...)

	return result
}

type PingServer struct {
	MyEndPoint  EndPoint
	PrivKeyPath string
	PrivKey     *ecdsa.PrivateKey	// TODO make this private
}

func (pingServer *PingServer) WrapPacket(node EthPacket) []byte {
	packetType := node.GetPacketType()
	encodedPacket := rlpencode(node.Pack())

	var message []byte
	message = append(message, packetType)
	message = append(message, encodedPacket...)
	digest := ethcrypto.Keccak512(message)

	r, s, err := ecdsa.Sign(rand.Reader, pingServer.PrivKey, digest)
	if err != nil {
		panic(fmt.Sprintf("unable to sign! %v", err))
	}
	fmt.Printf("r: %v   %v\n", r.String(), len(r.Bytes()))
	fmt.Printf("s: %v   %v\n", s.String(), len(s.Bytes()))

	var sig []byte
	sig = append(sig, r.Bytes()...)
	sig = append(sig, s.Bytes()...)

	var hash []byte
	hash = append(hash, sig...)
	hash = append(hash, message...)
	payloadHash := ethcrypto.Keccak512(hash)

	var result []byte
	result = append(result, payloadHash...)
	result = append(result, sig...)
	fmt.Printf("sig1: %v\n", sig)
	result = append(result, message...)

	fmt.Printf("message1: %v    %v\n", len(message), message)

	return result
}

func (pingServer *PingServer) UnwrapPacket(data []byte) (EthPacket, error) {
	payloadHash := data[:64]
	sig := data[64:128]
	fmt.Printf("sig2: %v\n", sig)
	message := data[128:155] // TODO do not hardcode length
	packetType := message[0]
	fmt.Printf("message2: %v    %v\n", len(message), message)
	var hash []byte
	hash = append(hash, sig...)
	hash = append(hash, message...)
	expectedPayloadHash := ethcrypto.Keccak512(hash)

	if bytes.Equal(payloadHash, expectedPayloadHash) == false {
		fmt.Printf("actual payload hash:%v    %v\n", len(payloadHash), payloadHash)
		fmt.Printf("expected payload hash:%v  %v\n", len(expectedPayloadHash), expectedPayloadHash)
		panic(fmt.Sprintf("hash mismatch"))
	}

	pubkey := &pingServer.PrivKey.PublicKey
	r := big.NewInt(0)
	r.SetBytes(sig[:32])
	s := big.NewInt(0)
	s.SetBytes(sig[32:])
	fmt.Printf("r2: %v\ns2: %v\n", r.String(), s.String())
	ok := ecdsa.Verify(pubkey, ethcrypto.Keccak512(message), r, s)
	if !ok {
		fmt.Printf("signature verification failed!\n")
	}

	if packetType != PINGNODE_PACKET_TYPE {
		panic(fmt.Sprintf("expected ping packet type (%v), got %v", PINGNODE_PACKET_TYPE, packetType))
	}

	fmt.Printf("Passed checks!\n")

	decodedMessage := rlpdecode(message)
	fmt.Printf("decoded message: %v\n", decodedMessage)

	return nil, nil
}

func (pingServer *PingServer) ping(endPoint EndPoint) {
	fmt.Println("pinging...")

	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("127.0.0.1"),
		Port: 30303,
	}

	conn, err := net.DialUDP("udp", nil, udpAddr)
	if err != nil {
		panic(fmt.Sprintf("failed to connect to address: %v - %v\n", endPoint.Ip.String(), err))
	}

	ping := PingPacket{
		pingServer.MyEndPoint,
		endPoint,
	}

	wrappedPacket := pingServer.WrapPacket(ping)
	if err != nil {
		panic(fmt.Sprintf("oh fuck we cant wrap dawg: %v\n", err))
	}

	n, err := conn.Write(wrappedPacket)
	if err != nil {
		panic(fmt.Sprintf("failed to write to socket: %v\n", err))
	}
	fmt.Printf("wrote %v bytes to socket\n", n)

	conn.Close()
}

func (pingServer *PingServer) Listen(protocol string, addr string) {

	// TODO clean this up
	udpAddr := &net.UDPAddr{
		IP:   net.ParseIP("0.0.0.0"),
		Port: 30303,
	}

	listener, err := net.ListenUDP(protocol, udpAddr)
	if err != nil {
		panic(fmt.Sprintf("Cannot listen on addr: %v - %v\n", addr, err))
	}

	fmt.Printf("Listening...\n")
	for {
		data := make([]byte, 1280)
		n, addr, err := listener.ReadFromUDP(data)
		if err != nil {
			fmt.Printf("error reading connection: %v\n", err)
			return
		}
		fmt.Printf("*read %v bytes from %v\n", n, addr)
		pingServer.handlePing(data)
	}
}

func (pingServer *PingServer) handlePing(data []byte) {
	pingServer.UnwrapPacket(data)
}

func main() {
	p256 := elliptic.P256()
	priv, err := ecdsa.GenerateKey(p256, rand.Reader)
	if err != nil {
		panic(fmt.Sprintf("unable to generate key: %v", err))
	}
	ioutil.WriteFile("./private.key", []byte(fmt.Sprintf("%v", priv)), 0644)

	myEndPoint := EndPoint{
		net.ParseIP("127.0.0.1"),
		30303,
		30303,
	}

	theirEndPoint := EndPoint{
		net.ParseIP("127.0.0.1"),
		30303,
		30303,
	}

	fmt.Printf("PRIVATE KEY: %v\n", priv)

	server := PingServer{
		MyEndPoint:  myEndPoint,
		PrivKeyPath: "./private.key",
		PrivKey:     priv,
	}

	var wg sync.WaitGroup
	wg.Add(1)

	go func() {
		server.Listen("udp", "0.0.0.0:30303")
	}()

	time.Sleep(2 * time.Second)
	server.ping(theirEndPoint)

	fmt.Println("waiting for wg\n")
	wg.Wait()
	fmt.Println("done\n")
}

func rlpencode(b []byte) []byte {
	result, err := rlp.EncodeToBytes(b)
	if err != nil {
		panic(fmt.Sprintf("failed to RLP encode: %v\n", err))
	}
	return result
}

func rlpdecode(b []byte) EthPacket {
	//var decodedBytes []byte
	node := &PingPacket{}
	err := rlp.DecodeBytes(b, node)
	if err != nil {
		panic(fmt.Sprintf("failed to RLP decode: %v\n", err))
	}
	return node
}
