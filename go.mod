module storj.io/storj

// force specific versions for minio
require (
	github.com/btcsuite/btcutil v0.0.0-20180706230648-ab6388e0c60a
	github.com/garyburd/redigo v1.0.1-0.20170216214944-0d253a66e6e1 // indirect
	github.com/go-ole/go-ole v1.2.1 // indirect
	github.com/graphql-go/graphql v0.7.6
	github.com/hanwen/go-fuse v0.0.0-20181027161220-c029b69a13a7

	github.com/minio/minio v0.0.0-20180508161510-54cd29b51c38
	github.com/segmentio/go-prompt v1.2.1-0.20161017233205-f0d19b6901ad
)

exclude gopkg.in/olivere/elastic.v5 v5.0.72 // buggy import, see https://github.com/olivere/elastic/pull/869

require (
	github.com/Shopify/go-lua v0.0.0-20181106184032-48449c60c0a9
	github.com/Shopify/toxiproxy v2.1.4+incompatible // indirect
	github.com/StackExchange/wmi v0.0.0-20180725035823-b12b22c5341f // indirect
	github.com/alicebob/gopher-json v0.0.0-20180125190556-5a6b3ba71ee6 // indirect
	github.com/alicebob/miniredis v0.0.0-20180911162847-3657542c8629
	github.com/boltdb/bolt v1.3.1
	github.com/cheggaaa/pb v1.0.5-0.20160713104425-73ae1d68fe0b
	github.com/djherbis/atime v1.0.0 // indirect
	github.com/eapache/go-resiliency v1.1.0 // indirect
	github.com/eapache/go-xerial-snappy v0.0.0-20180814174437-776d5712da21 // indirect
	github.com/eapache/queue v1.1.0 // indirect
	github.com/eclipse/paho.mqtt.golang v1.1.1 // indirect
	github.com/fatih/color v1.7.0
	github.com/go-redis/redis v6.14.1+incompatible
	github.com/gogo/protobuf v1.2.1
	github.com/golang-migrate/migrate/v3 v3.5.2
	github.com/golang/mock v1.2.0
	github.com/golang/protobuf v1.2.0
	github.com/golang/snappy v0.0.1 // indirect
	github.com/gomodule/redigo v2.0.0+incompatible // indirect
	github.com/google/go-cmp v0.2.0
	github.com/gopherjs/gopherjs v0.0.0-20181103185306-d547d1d9531e // indirect
	github.com/gorilla/handlers v1.4.0 // indirect
	github.com/gorilla/mux v1.7.0 // indirect
	github.com/gorilla/rpc v1.1.0 // indirect
	github.com/howeyc/gopass v0.0.0-20170109162249-bf9dde6d0d2c // indirect
	github.com/inconshreveable/go-update v0.0.0-20160112193335-8152e7eb6ccf // indirect
	github.com/influxdata/influxdb v1.7.5 // indirect
	github.com/influxdata/platform v0.0.0-20190117200541-d500d3cf5589 // indirect
	github.com/influxdb/influxdb v1.7.5 // indirect
	github.com/jbenet/go-base58 v0.0.0-20150317085156-6237cf65f3a6
	github.com/jtolds/go-luar v0.0.0-20170419063437-0786921db8c0
	github.com/jtolds/monkit-hw v0.0.0-20190108155550-0f753668cf20
	github.com/klauspost/cpuid v0.0.0-20180405133222-e7e905edc00e // indirect
	github.com/klauspost/reedsolomon v0.0.0-20180704173009-925cb01d6510 // indirect
	github.com/lib/pq v1.0.0
	github.com/loov/hrtime v0.0.0-20181214195526-37a208e8344e
	github.com/loov/plot v0.0.0-20180510142208-e59891ae1271
	github.com/mattn/go-sqlite3 v1.10.0
	github.com/minio/cli v1.3.0
	github.com/minio/dsync v0.0.0-20180124070302-439a0961af70 // indirect
	github.com/minio/highwayhash v0.0.0-20180501080913-85fc8a2dacad // indirect
	github.com/minio/lsync v0.0.0-20180328070428-f332c3883f63 // indirect
	github.com/minio/mc v0.0.0-20180926130011-a215fbb71884 // indirect
	github.com/minio/minio-go v6.0.3+incompatible
	github.com/minio/sha256-simd v0.0.0-20171213220625-ad98a36ba0da // indirect
	github.com/minio/sio v0.0.0-20180327104954-6a41828a60f0 // indirect
	github.com/mr-tron/base58 v0.0.0-20180922112544-9ad991d48a42
	github.com/nats-io/nats v1.6.0 // indirect
	github.com/nsf/jsondiff v0.0.0-20160203110537-7de28ed2b6e3
	github.com/nsf/termbox-go v0.0.0-20190121233118-02980233997d
	github.com/op/go-logging v0.0.0-20160315200505-970db520ece7 // indirect
	github.com/pkg/errors v0.8.1 // indirect
	github.com/pkg/profile v1.2.1 // indirect
	github.com/rcrowley/go-metrics v0.0.0-20181016184325-3113b8401b8a // indirect
	github.com/rs/cors v1.5.0 // indirect
	github.com/sbinet/go-python v0.0.0-20190327143913-ddccf6692cfa // indirect
	github.com/shirou/gopsutil v2.17.12+incompatible
	github.com/sirupsen/logrus v1.3.0 // indirect
	github.com/skyrings/skyring-common v0.0.0-20160929130248-d1c0bb1cbd5e
	github.com/spacemonkeygo/errors v0.0.0-20171212215202-9064522e9fd1 // indirect
	github.com/spf13/cobra v0.0.3
	github.com/spf13/pflag v1.0.3
	github.com/spf13/viper v1.2.1
	github.com/streadway/amqp v0.0.0-20180806233856-70e15c650864 // indirect
	github.com/stretchr/testify v1.3.0
	github.com/tidwall/gjson v1.1.3 // indirect
	github.com/tidwall/match v0.0.0-20171002075945-1731857f09b1 // indirect
	github.com/vivint/infectious v0.0.0-20190108171102-2455b059135b
	github.com/yuin/gopher-lua v0.0.0-20180918061612-799fa34954fb // indirect
	github.com/zeebo/admission v0.0.0-20180821192747-f24f2a94a40c
	github.com/zeebo/errs v1.1.0
	github.com/zeebo/float16 v0.1.0 // indirect
	github.com/zeebo/incenc v0.0.0-20180505221441-0d92902eec54 // indirect
	go.uber.org/zap v1.9.1
	golang.org/x/crypto v0.0.0-20190225124518-7f87c0fbb88b
	golang.org/x/net v0.0.0-20190225153610-fe579d43d832
	golang.org/x/sync v0.0.0-20181221193216-37e7f081c4d4
	golang.org/x/sys v0.0.0-20190225065934-cc5685c2db12
	golang.org/x/text v0.3.1-0.20180807135948-17ff2d5776d2 // indirect
	golang.org/x/time v0.0.0-20181108054448-85acf8d2951c // indirect
	golang.org/x/tools v0.0.0-20190225234524-2dc4ef2775b8
	google.golang.org/genproto v0.0.0-20190219182410-082222b4a5c5 // indirect
	google.golang.org/grpc v1.19.0
	gopkg.in/Shopify/sarama.v1 v1.18.0 // indirect
	gopkg.in/cheggaaa/pb.v1 v1.0.25 // indirect
	gopkg.in/olivere/elastic.v5 v5.0.76 // indirect
	gopkg.in/spacemonkeygo/monkit.v2 v2.0.0-20180827161543-6ebf5a752f9b
	gopkg.in/yaml.v2 v2.2.2 // indirect
)
