module github.com/jaredfolkins/honeytrap

go 1.11

require (
	github.com/AndreasBriese/bbloom v0.0.0-20170702084017-28f7e881ca57 // indirect
	github.com/BurntSushi/toml v0.3.0
	github.com/Logicalis/asn1 v0.0.0-20160307192209-c9c836c1a3cd
	github.com/PromonLogicalis/asn1 v0.0.0-20190312173541-d60463189a56 // indirect
	github.com/Shopify/sarama v1.16.0
	github.com/Shopify/toxiproxy v2.1.4+incompatible // indirect
	github.com/boltdb/bolt v1.3.1
	github.com/dgraph-io/badger v0.0.0-20180227002726-94594b20babf
	github.com/dgryski/go-farm v0.0.0-20180109070241-2de33835d102 // indirect
	github.com/dimfeld/httptreemux v5.0.1+incompatible // indirect
	github.com/dutchcoders/gobus v0.0.0-20180915095724-ece5a7810d96
	github.com/eapache/go-resiliency v1.0.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20160609142408-bb955e01b934 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/elazarl/go-bindata-assetfs v1.0.0 // indirect
	github.com/fatih/color v1.6.0
	github.com/fortytw2/leaktest v1.3.0 // indirect
	github.com/fuyufjh/splunk-hec-go v0.3.3
	github.com/glycerine/goconvey v0.0.0-20190410193231-58a59202ab31 // indirect
	github.com/glycerine/rbuf v0.0.0-20171031012212-54320fe9f6f3
	github.com/go-asn1-ber/asn1-ber v0.0.0-20170511165959-379148ca0225
	github.com/golang/protobuf v0.0.0-20180202184318-bbd03ef6da3a
	github.com/golang/snappy v0.0.0-20170215233205-553a64147049 // indirect
	github.com/google/btree v1.0.0 // indirect
	github.com/google/gopacket v1.1.14
	github.com/google/netstack v0.0.0
	github.com/gorilla/websocket v1.2.0
	github.com/honeytrap/protocol v0.0.0-20190410072324-219b95413db0
	github.com/kr/pretty v0.1.0 // indirect
	github.com/labstack/gommon v0.2.9
	github.com/mailru/easyjson v0.0.0-20171120080333-32fa128f234d // indirect
	github.com/mattn/go-isatty v0.0.8
	github.com/miekg/dns v1.0.4
	github.com/mimoo/StrobeGo v0.0.0-20171206114618-43f0c284a7f9 // indirect
	github.com/mimoo/disco v0.0.0-20180114190844-15dd4b8476c9
	github.com/op/go-logging v0.0.0-20160211212156-b2cb9fa56473
	github.com/pierrec/lz4 v0.0.0-20171218195038-2fcda4cb7018 // indirect
	github.com/pierrec/xxHash v0.1.1 // indirect
	github.com/pkg/errors v0.8.0 // indirect
	github.com/pkg/profile v1.2.1
	github.com/rcrowley/go-metrics v0.0.0-20180125231941-8732c616f529 // indirect
	github.com/rs/xid v0.0.0-20170604230408-02dd45c33376
	github.com/satori/go.uuid v1.2.0
	github.com/smartystreets/goconvey v0.0.0-20190330032615-68dc04aab96a // indirect
	github.com/songgao/packets v0.0.0-20160404182456-549a10cd4091
	github.com/songgao/water v0.0.0-20180221190335-75f112d19d5a
	github.com/streadway/amqp v0.0.0-20180315184602-8e4aba63da9f
	github.com/vishvananda/netlink v1.0.0
	github.com/vishvananda/netns v0.0.0-20171111001504-be1fbeda1936 // indirect
	github.com/yuin/gopher-lua v0.0.0-20190206043414-8bfc7677f583
	golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2
	golang.org/x/sync v0.0.0-20190412183630-56d357773e84 // indirect
	golang.org/x/time v0.0.0-20170927054726-6dc17368e09b
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/lxc/go-lxc.v2 v2.0.0-20190324192716-2f350e4a2980
	gopkg.in/olivere/elastic.v5 v5.0.65
	gopkg.in/urfave/cli.v1 v1.20.0
)

replace github.com/google/netstack => github.com/honeytrap/netstack v0.0.0-20190414201528-9ea5e4d2258f
