# pcap utils

A simple API for parse the pcap file, 0.1 version support HTTP, you may add your
protocol support eg: binlog, mysql etc.

## API:
```scala
import pcap.HttpParser._
import pcap.Packet.PcapRecord

val records: List[PcapRecord] = pcap.parsePcapRecords("/path/to/pcapfile") 

val events: List[HttpEvent] = pcap.parseHttpEvents("/path/to/pcapfile")

val paris: List[(HttpRequest, HttpResponse)] = pcap.parseHttpPairs("/path/to/pcapfile");

```


