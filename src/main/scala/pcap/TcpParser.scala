package pcap

import Packet._

import scala.collection.mutable.ListBuffer
import scala.util.matching.Regex

object TcpParser {

    object TcpOnewayStream {
        val S_SYNC = 1
        val S_FIN = 2
    }


    class TcpOnewayStream (val srcIP: IP, val srcPort: Port, val destIP: IP, val destPort: Port ) {

        import TcpOnewayStream._

        val buffer = ListBuffer[Byte]()
        var bufferStartSeq: Long = -1
        var lastPacketTs: Option[TimeUsec] = None

        var status: Int = 0

        protected def clearBuffer(): Unit = {
            val bufferEndSeq = bufferStartSeq + buffer.size
            buffer.clear()
            bufferStartSeq = bufferEndSeq
        }

        def append(packet: TCPPacket): Unit = {
            lastPacketTs = Some(packet.ts)
            val flags = packet.tcpFlags
            // SYN
            if ((flags & TCPPacket.SYN) != 0) {
                status = S_SYNC
                bufferStartSeq = packet.sequence + 1
            }
            else if ((flags & TCPPacket.FIN) != 0) {
                status = S_FIN
                bufferStartSeq = packet.sequence + 1
            }
            else if ((flags & TCPPacket.ACK) != 0) {
                if (status != S_SYNC) {
                    warn(s"packet ${packet.parent.parent.parent.seq} missing pred SYNC")
                    status = S_SYNC
                    bufferStartSeq = packet.sequence
                    clearBuffer()
                }
                val seq = packet.sequence
                val expectSeq = bufferStartSeq + buffer.size
                if (expectSeq == seq) {
                    buffer.appendAll(packet.contentAsBytes)
                }
                else { // wrong packet, ignore
                    warn(s"packet:${packet.parent.parent.parent.seq}  sequence:${seq} expect:${expectSeq}, ignore")
                    buffer.clear()
                    buffer.appendAll(packet.contentAsBytes)
                    bufferStartSeq = packet.sequence
                }
            }

        }
    }

    def warn(message: String) = Console.err.println(message)

}
