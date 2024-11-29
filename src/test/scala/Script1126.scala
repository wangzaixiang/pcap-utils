
import pcap.*
import pcap.Packet.TCPPacketExtractor

import java.sql.Timestamp
import scala.collection.mutable.ArrayBuffer

class StreamBuffer {

    val buffer = ArrayBuffer[Byte]()
    var seqNo = -1L
    val pendings = ArrayBuffer[(Long, Array[Byte])]()

    def length = buffer.length

    def apply(index: Int): Byte = buffer(index)

    def content: Array[Byte] = buffer.toArray

    def append(seq: Long, bytes: Array[Byte]): Unit = {
        if bytes.length == 0 then
            ; // do nothing
        else if seqNo == -1L then
            seqNo = seq
            buffer.appendAll(bytes)
            seqNo += bytes.length
        else if seq == seqNo then
            buffer.appendAll(bytes)
            seqNo += bytes.length

            var p = 0
            while p < pendings.size do
                val (seq, bytes) = pendings(p)
                if seq == seqNo then
                    buffer.appendAll(bytes)
                    seqNo += bytes.length
                    pendings.remove(p)
                else
                    p += 1

        else if seq + bytes.length <= seqNo then
            ;
        // discard
        else if seq + bytes.length > seqNo then
            pendings.append((seq, bytes))

    }
}


@main
def parse127(): Unit = {

    val file127 = "/tmp/20241127/12720241127.pcap"
    val file128 = "/tmp/20241127/12820241127.pcap"

    val records127: List[Packet.PcapRecord] = parsePcapRecords(file127)
    val _127to128 = collection.mutable.Map[(String, String), StreamBuffer]()
    val _127from128 = collection.mutable.Map[(String, String), StreamBuffer]()

    val beginTsSec = (java.sql.Timestamp.valueOf("2024-11-27 17:34:24").getTime / 1000).toInt
    val beginTsUSec = 0
    val endTsSec = (java.sql.Timestamp.valueOf("2024-11-27 17:37:11").getTime / 1000).toInt
    val endTsUSec = 0

    var first = true
    var num1, num2: Long = 0
    records127.foreach {
        case p @ TCPPacketExtractor(x: Packet.TCPPacket)  if x.srcIP.toString == "10.69.1.127" && x.destIP.toString == "10.69.1.128"
            && p.tsSec >= beginTsSec && p.tsSec < endTsSec =>
            val bytes: Array[Byte] = x.contentAsBytes
            val key = (x.srcPort.toString, x.destPort.toString)
            val buffer = _127to128.getOrElseUpdate(key, StreamBuffer())

            buffer.append(x.sequence, bytes)
            num1 += p.underlayer.length

        case p @ TCPPacketExtractor(x: Packet.TCPPacket)  if x.destIP.toString == "10.69.1.127" && x.srcIP.toString == "10.69.1.128"
            && p.tsSec >= beginTsSec && p.tsSec < endTsSec =>
            val bytes: Array[Byte] = x.contentAsBytes
            val key = (x.srcPort.toString, x.destPort.toString)
            val buffer = _127from128.getOrElseUpdate(key, StreamBuffer())

//            if first && x.srcPort.value == 41062 && x.destPort.value == 40101 &&
//                buffer.length + bytes.length > 44117 then
//                first = false
//                println(f"127.pcap at ${p.tsSec.toLong*1000}%tT.${p.tsUSec} offset:${44117 - buffer.length}")

//            if first && x.srcPort.value == 46854 && x.destPort.value == 38633 && buffer.length + bytes.length > 14083910 then
//                println("127.pcap at %tT.%d offset:%d".formatted(p.tsSec.toLong*1000, p.tsUSec, 14083910 - buffer.length))
//                first = false

//            if key._1 == "41062" && key._2 == "40101" then
//                println("1");

            buffer.append(x.sequence, bytes)
            num1 += p.underlayer.length

        case p@_ =>
            num2 += p.underlayer.length
    }

    println("num1: %d, num2: %d".format(num1, num2))


    val records128 = parsePcapRecords(file128)
    val _128from127 = collection.mutable.Map[(String, String), StreamBuffer]()
    val _128to127 = collection.mutable.Map[(String, String), StreamBuffer]()
    first = true
    records128.foreach {
        case p @ TCPPacketExtractor(x: Packet.TCPPacket)  if x.srcIP.toString == "10.69.1.127" && x.destIP.toString == "10.69.1.128"
            && p.tsSec >= beginTsSec && p.tsSec < endTsSec =>
            val bytes = x.contentAsBytes
            val key = (x.srcPort.toString, x.destPort.toString)
            val buffer = _128from127.getOrElseUpdate(key, StreamBuffer())

            if first && x.srcPort.value == 46854 && x.destPort.value == 38633 && buffer.length + bytes.length > 14083910 then
                println("127.pcap at $tT.%d offset:%d".formatted(p.tsSec.toLong*1000, p.tsUSec, 14083910 - buffer.length))
                first = false

            buffer.append(x.sequence, bytes)

        case p @ TCPPacketExtractor(x: Packet.TCPPacket)  if x.destIP.toString == "10.69.1.127" && x.srcIP.toString == "10.69.1.128"
            && p.tsSec >=beginTsSec && p.tsSec < endTsSec =>
            val bytes = x.contentAsBytes
            val key = (x.srcPort.toString, x.destPort.toString)
            val buffer = _128to127.getOrElseUpdate(key, StreamBuffer())
            buffer.append(x.sequence, bytes)

        case _ =>
    }


    def diff(a: Array[Byte], b: Array[Byte]): (Int, Int) = {

        val max = a.length min b.length
        var start = 0
        while start < max && a(start) == b(start) do
            start += 1
        start

        var end = max - 1
        while end >= 0 && a(end) == b(end) do
            end -= 1
        end

        (start, end)
    }

    def showDiff(label: String, a: Array[Byte], b: Array[Byte]): Unit = {
        if a.toList != b.toList then
            val (start, end) = diff(a, b)
            if a.length == b.length then
                println("%s diff at (%d..%d)".format(label, start, end))
            else
                println("%s diff at (%d..%d) a.length: %d, b.length: %d".format(label, start, end, a.length, b.length))
    }

    var diffCount = 0
    _127to128.keys.foreach { key =>
        val to128: StreamBuffer = _127to128(key)
        val from127: StreamBuffer = _128from127(key)

        if to128.pendings.nonEmpty || from127.pendings.nonEmpty then
            println(s"check $key has pending")

        if to128.content.length != from127.content.length then
            diffCount += 1
            showDiff(s"127:${key._1} -> 128:${key._2}", from127.content, to128.content)

    }

    _128to127.keys.foreach { key =>
        val to127: StreamBuffer = _128to127(key)
        val from128: StreamBuffer = _127from128(key)

        if to127.pendings.nonEmpty || from128.pendings.nonEmpty then
            println(s"check $key has pending")

        if to127.content.length != from128.content.length then
            diffCount += 1
            showDiff(s"128:${key._1} -> 127:${key._2}", from128.content, to127.content)
    }

    if diffCount == 0 then
        println("All data are same")

}
