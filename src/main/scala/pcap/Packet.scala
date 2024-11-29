package pcap

import java.io.{EOFException, FileInputStream, FileOutputStream, IOException, InputStream, OutputStreamWriter, PrintWriter}

import scala.collection.mutable

object Packet {


    case class TimeUsec(tsSec:Int, tsUsec: Int) extends Comparable[TimeUsec] {
        override def toString() = {
            val ms = (tsSec.toLong & 0xFFFF_FFFFL) * 1000 + tsUsec / 1000
            val us = tsUsec % 1000
            f"${ms}%tF ${ms}%tT.${tsUsec}%06d"
        }

        def timeMillis = (tsSec.toLong & 0xFFFF_FFFFL) * 1000 + tsUsec / 1000

        override def compareTo(o: TimeUsec): Int = {
            val diff  = (tsSec - o.tsSec).toLong * 1000_000L + (tsUsec - o.tsUsec).toLong
            if(diff > 0) 1
            else if(diff < 0) -1
            else 0
        }
    }

    class IP(val value: Int) extends AnyVal {
        override def toString = {
            val b0 = (value >> 24) & 0xFF
            val b1 = (value >> 16) & 0xFF
            val b2 = (value >>8) & 0xFF
            val b3 = value & 0xFF
            s"${b0}.${b1}.${b2}.${b3}"
        }
    }
    // realy only 16bit
    class Port(val value: Int) extends AnyVal {
        override def toString: String = value.toString
    }

    case class ByteBuffer(buffer: Array[Byte], from: Int, length: Int) {

        override def toString: String = new String(buffer, from, length, "UTF-8")

        override def equals(obj: Any): Boolean = obj match {
            case x: ByteBuffer if x.length == length =>
                var pos = 0
                var same = true
                while(pos < length && same) {
                    if(buffer(from + pos) != x.buffer(x.from + pos))
                        same = false
                    pos += 1
                }
                same
            case _ => false
        }

        def getBytes: Array[Byte] = {
            val result = new Array[Byte](length)
            System.arraycopy(buffer, from, result, 0, length)
            result
        }


        def readPcapI32(offset: Int): Int = {
            assert(offset >= 0 && offset + 4 <= length)
            (buffer(from + offset) & 0xFF) |
              ((buffer(from + offset + 1) & 0xFF) << 8) |
              ((buffer(from + offset + 2) & 0xFF) << 16) |
              ((buffer(from + offset + 3) & 0xFF) << 24)
        }

        def readPcapI16(offset: Int): Short = {
            assert(offset >= 0 && offset + 2 <= length)
            ( (buffer(from + offset) & 0xFF) |
              ((buffer(from + offset + 1) & 0xFF) << 8) ).toShort
        }

        def readI32(offset: Int): Int = {
            assert(offset >= 0 && offset + 4 <= length)
            (buffer(from + offset + 3) & 0xFF) |
              ((buffer(from + offset + 2) & 0xFF) << 8) |
              ((buffer(from + offset + 1) & 0xFF) << 16) |
              ((buffer(from + offset) & 0xFF) << 24)
        }

        def readI64(offset: Int): Long = {
            assert(offset >= 0 && offset + 8 <= length)
            (buffer(from + offset + 7).toLong & 0xFF)  |
              ((buffer(from + offset + 6).toLong & 0xFF) << 8) |
              ((buffer(from + offset + 5).toLong & 0xFF) << 16) |
              ((buffer(from + offset + 4).toLong & 0xFF) << 24) |
              ((buffer(from + offset + 3).toLong & 0xFF) << 32) |
              ((buffer(from + offset + 2).toLong & 0xFF) << 40) |
              ((buffer(from + offset + 1).toLong & 0xFF) << 48) |
              ((buffer(from + offset) & 0xFF).toLong << 54)
        }

        def readI16(offset: Int): Short = {
            assert(offset >= 0 && offset + 2 <= length)
            ( (buffer(from + offset + 1) & 0xFF) |
              ((buffer(from + offset) & 0xFF) << 8) ).toShort
        }

        def readI8(offset: Int): Byte = {
            assert(offset >= 0 && offset < length)
            buffer(from + offset)
        }

        def slice(offset: Int, length: Int): ByteBuffer = {
            assert( offset >= 0 && offset <= this.length)
            assert( offset + length <= this.length )
            ByteBuffer(buffer, from + offset, length)
        }

        def slice(offset: Int): ByteBuffer = slice(offset, length - offset)

    }

    trait Packet {
        val underlayer: ByteBuffer
    }

    case class PcapRecord(seq: Int, underlayer: ByteBuffer) extends Packet {

        val tsSec: Int = underlayer.readPcapI32(0)
        val tsUSec: Int = underlayer.readPcapI32(4)

        val inclLen: Int = underlayer.readPcapI32((8))

        val origLen: Int = underlayer.readPcapI32(12)

        val content = underlayer.slice(16)

        def ts: TimeUsec = TimeUsec(tsSec, tsUSec)

    }
    class EthernetPacket(val underlayer: ByteBuffer, val parent: PcapRecord) extends Packet {
        val src: Long = {
            val h2 = underlayer.readI16(0) & 0xFFFF
            val l4 = underlayer.readI32(2).toLong & 0xFFFF_FFFFL
            (h2.toLong << 16) | (l4)
        }
        val dest: Long = {
            val h2 = underlayer.readI16(6) & 0xFFFF
            val l4 = underlayer.readI32(8).toLong & 0xFFFF_FFFFL
            (h2.toLong << 16) | (l4)
        }
        val content = underlayer.slice(14)

        def isIP() = {
            underlayer.readI16(12) == 0x0800.toShort
        }
    }
    object EthernetPacketExtractor {
        def unapply(arg: PcapRecord): Option[EthernetPacket] = {
            if( arg.content.readI16(12) == 0x0800 )
                Some( new EthernetPacket(arg.content, arg))
            else None
        }
    }
    class IPPacket(val underlayer: ByteBuffer, val parent: EthernetPacket) extends Packet {

        val version = (underlayer.readI8(0) & 0xFF) >> 4
        val headerLength = (underlayer.readI8(0) & 0x0F) * 4
        val tos = underlayer.readI8(1)
        val totalLength = underlayer.readI16(2) & 0xFFFF
        val protocol = underlayer.readI8(9)
        val srcIP = new IP(underlayer.readI32(12))
        val destIP = new IP(underlayer.readI32(16))
        val content = underlayer.slice(headerLength)

    }

    object IPPacketExtractor {
        def unapply(arg: EthernetPacket): Option[IPPacket] = {
            if(arg.isIP())
                Some(new IPPacket(arg.content, arg))
            else None
        }
        def unapply(arg: PcapRecord): Option[IPPacket] = {
            arg match {
                case EthernetPacketExtractor(IPPacketExtractor(ip)) => Some(ip)
                case _ => None
            }
        }
    }

    object TCPPacketExtractor {

        def unapply(ip: IPPacket): Option[TCPPacket] = {
            if(ip.protocol == 6)
                Some( new TCPPacket(ip.content, ip) )
            else None
        }
        def unapply(ether: EthernetPacket): Option[TCPPacket] = {
            ether match {
                case IPPacketExtractor(TCPPacketExtractor(tcp)) => Some(tcp)
                case _ => None
            }
        }
        def unapply(record: PcapRecord): Option[TCPPacket] = {
            record match {
                case EthernetPacketExtractor(IPPacketExtractor(TCPPacketExtractor(tcp))) =>
                    Some(tcp)
                case _ => None
            }
        }
    }

    object TCPPacket {
        val URG = 32
        val ACK = 16
        val PSH = 8
        val RST = 4
        val SYN = 2
        val FIN = 1
    }

    class TCPPacket(val underlayer: ByteBuffer, val parent: IPPacket) extends Packet {


        val srcPort = new Port(underlayer.readI16(0) & 0xFFFF)
        val destPort = new Port(underlayer.readI16(2) & 0xFFFF)
        val sequence: Long = underlayer.readI32(4).toLong & 0xFFFF_FFFFL
        val acknowledge: Long = underlayer.readI32(8).toLong & 0xFFFF_FFFFL
        val dataOffset = (underlayer.readI8(12) & 0xFF) >> 2 // >> 4 * 4
        val tcpFlags = underlayer.readI8(13)
        val window = underlayer.readI16(14)

        val content = underlayer.slice(dataOffset)

        def srcIP = parent.srcIP
        def destIP = parent.destIP
        def ts = parent.parent.parent.ts

        def contentAsBytes: Array[Byte]= {
            content.getBytes
        }
    }

    case class PcapFile
    (
        magicNumber: Int,
        versionMajor: Short,
        versionMinor: Short,
        thisZone: Int,
        sigfigs: Int,
        snaplen: Int,
        network: Int,
        records: List[PcapRecord]
    )

    object PcapFile {

        def readPcapI32(in: InputStream): Int = {
            val bytes = new Array[Byte](4)
            if( in.read(bytes) < 4 )
                throw new EOFException()
            (bytes(0) & 0xFF) | ( (bytes(1) & 0xFF) << 8) | ( (bytes(2) & 0xFF) << 16) | ( (bytes(3) & 0xFF) << 24 )
        }

        def readPcapI16(in: InputStream): Short = {
            val bytes = new Array[Byte](2)
            if( in.read(bytes) < 2 )
                throw new EOFException()
            ((bytes(0) & 0xFF) | ( (bytes(1) & 0xFF) << 8)).toShort
        }

        def parseRecord(seq: Int, in: InputStream): Option[PcapRecord] = try {
            val header = new Array[Byte](16)
            if( in.read(header) != 16 )
                throw new EOFException()

            val inclLen =   // packet length
                (header(8) & 0xFF) |
                  ((header(8+1) & 0xFF) << 8) |
                  ((header(8+2) & 0xFF) << 16) |
                  ((header(8+3) & 0xFF) << 24)


            val data = new Array[Byte](16 + inclLen)
            System.arraycopy(header, 0, data, 0, 16)

            if( in.read(data, 16, inclLen) != inclLen)
                throw new EOFException()

            Some( PcapRecord(seq, ByteBuffer(data, 0, data.length)) )
        } catch {
            case ex: EOFException => None
        }

        def apply(in: InputStream): PcapFile = {
            val magicNumber = readPcapI32(in)
            val versionMajor = readPcapI16(in)
            val versionMinor = readPcapI16(in)
            val thisZone = readPcapI32(in)
            val sigfigs = readPcapI32(in)
            val snaplen = readPcapI32(in)
            val network = readPcapI32(in)

            val buffer = collection.mutable.ListBuffer[PcapRecord]()

            var record: Option[PcapRecord] = None
            var seq = 0
            var cont = true
            while(cont) {
                seq += 1
                record = parseRecord(seq, in)
                if(record != None){
                    buffer.append(record.get)
                }
                else cont = false
            } // while(record != None)

            PcapFile(magicNumber, versionMajor, versionMinor, thisZone,
                sigfigs, snaplen, network, buffer.toList)
        }
    }


}
