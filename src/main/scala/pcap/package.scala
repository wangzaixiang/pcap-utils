import java.io.{FileInputStream, FileOutputStream}

import pcap.HttpParser.{HttpEvent, HttpOneWayStream, HttpRequest, HttpResponse}
import pcap.Packet.{IP, PcapFile, PcapRecord, Port, TCPPacket, TCPPacketExtractor}
import pcap.TcpParser.TcpOnewayStream

import scala.collection.mutable

/**
 * usage:
 *
 *   List[PcapRecord] pcap.parsePcap( pcapFile )
 *
 *   1. single packet level: EthernetPacket/IPPacket/TCPPacket
 *   2. Http packet level: HttpRequest/HttpResponse
 *
 *   List[HttpEvent] pcap.parseHttpEvent( pcapFile )
 *
 *   List[(req, resp)] pcap.parseHttp( pcapFile )
 */

package pcap {

    def parsePcapRecords(pcapFile: String) : List[PcapRecord] = {
        val in = new FileInputStream(pcapFile)
        val pc  = PcapFile(in)
        pc.records
    }

    def parseHttpEvents(pcapFile: String): List[HttpEvent] = {

        val streams = mutable.Map[(IP, Port, IP, Port), TcpOnewayStream]()
        val events = mutable.ListBuffer[HttpEvent]()
        val callback = { (event: HttpEvent) => events.append(event); () }

        parsePcapRecords(pcapFile).foreach {
            case TCPPacketExtractor(x: TCPPacket) =>
                val key = (x.srcIP, x.srcPort, x.destIP, x.destPort)
                if(!(streams contains key)) {
                    val stream = new HttpOneWayStream(x.srcIP, x.srcPort, x.destIP, x.destPort, callback)
                    streams(key) = stream
                }
                val stream = streams(key)
                stream.append(x)
            case _ =>
        }

        events.toList
    }

    def parseHttpPairs(pcapFile: String): List[(HttpRequest, HttpResponse)] = {

        val httpEvents = parseHttpEvents(pcapFile)
        val pairs = mutable.Map[HttpRequest, HttpResponse]()
        val matched = mutable.Set[HttpEvent]()

        httpEvents.foreach {
            case x: HttpRequest if pairs.contains(x) == false =>
                httpEvents.find {
                    case y: HttpResponse =>
                        y.srcIP == x.destIP && y.srcPort == x.destPort &&
                        y.destIP == x.srcIP && y.destPort == x.srcPort &&
                        matched.contains(y) == false &&
                        y.ts.compareTo(x.ts) >= 0
                    case _ => false
                } match {
                    case Some(y: HttpResponse) =>
                        pairs(x) = y
                        matched.add(x)
                        matched.add(y)
                    case _ =>
                }
            case _ =>
        }

        pairs.toList.sortBy(_._1.ts)
    }

}
