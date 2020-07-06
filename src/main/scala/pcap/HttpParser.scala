package pcap

import pcap.Packet.{ByteBuffer, IP, Port, TimeUsec}
import pcap.TcpParser.TcpOnewayStream

import scala.collection.mutable.ListBuffer
import scala.util.matching.Regex

object HttpParser {


    trait HttpEventCallback {
        def process(event: HttpEvent)
    }


    sealed trait HttpEvent {
        def isPartial = false
    }
    case class HttpRequest
    (
      srcIP: IP,
      srcPort:Port,
      destIP: IP,
      destPort: Port,
      ts: TimeUsec,
      method: String,
      url: String,
      version: String,
      headers:Map[String, String],
      data: ByteBuffer
    ) extends HttpEvent {
        def sameContent(it: HttpRequest): Boolean = {
            method == it.method &&
              url == it.url &&
              version == it.version &&
              headers == it.headers &&
              data == it.data
        }

        override def toString: String = {
            val sb = new StringBuilder
            sb.append(s"[${ts}] [${srcIP}:${srcPort} -> ${destIP}:${destPort}] [${method} ${url}]\n")
            sb.append("  headers\n")
            headers.foreach { case (k,v) =>
                sb.append(s"    $k: $v\n")
            }
            if(data.length > 0) {
                sb.append("  data:\n")
                sb.append("    ==>" + data.toString + "<==\n")
            }
            sb.toString()
        }
    }

    case class HttpResponse
    (
      srcIP: IP,
      srcPort: Port,
      destIP: IP,
      destPort: Port,
      ts: TimeUsec,
      code: Int,
      message: String,
      version: String,
      headers: Map[String, String],
      data: ByteBuffer
    ) extends HttpEvent {
        override def toString: String = {
            val sb = new StringBuilder
            sb.append(s"[${ts}] [${destIP}:${destPort} <- ${srcIP}:${srcPort}] ${code} ${message}\n")
            sb.append("  headers\n")
            headers.foreach { case (k,v) =>
                sb.append(s"    $k: $v\n")
            }
            if(data.length > 0) {
                sb.append("  data:\n")
                sb.append("    ==>" + data.toString + "<==\n")
            }
            sb.toString()
        }
    }


    case class HttpRequestPartial() extends HttpEvent {
        override def isPartial = true
    }
    case class HttpResponsePartial() extends HttpEvent {
        override def isPartial: Boolean = true
    }

    private val REQ_LINE1_PATTERN = """(?m)^(GET|PUT|POST|HEAD|DELETE)\s+([^\s]+)\s+(HTTP/\d+.\d+)$""".r
    private val RESP_LINE1_PATTERN = """(?m)^(HTTP/\d+.\d+) (\d{3}) (.*)$""".r
    private val HEADER_PATTERN = """([^\s]+): (.*)""".r

    class HttpOneWayStream(srcIP: IP, srcPort: Port, destIP: IP, destPort: Port, callback: HttpEvent=>Unit
                          ) extends TcpOnewayStream(srcIP, srcPort, destIP, destPort) {

        override def append(packet: Packet.TCPPacket): Unit = {
            super.append(packet)

            val asStr = new String(buffer.toArray, "UTF-8")  // TODO support Charset

            val event =
                if(REQ_LINE1_PATTERN.findFirstMatchIn(asStr) != None) {
                    new RequestParser(this, buffer.toArray).parse()
                }
                else if(RESP_LINE1_PATTERN.findFirstMatchIn(asStr) != None) {
                    new ResponseParser(this, buffer.toArray).parse()
                }
                else None

            event match {
                case Some(x) if x.isPartial =>
                case Some(x) =>
                    if(callback != null) callback.apply(x)
                    clearBuffer();
                case None =>  // Not HTTP
                    clearBuffer()
            }
        }
    }

    case class Line(startPos: Int, eolPos: Int) {
        def asStr(underlayer: Array[Byte]): String = new String(underlayer, startPos, eolPos - startPos - 1)
    }

    abstract class Parser(stream:TcpOnewayStream, firstLinePattern: Regex, buffer: Array[Byte]) {

        var pos = 0

        def nextLine(): Option[Line] = {
            val begin = pos
            while( buffer(pos) != 0x0d )
                pos += 1

            if(buffer(pos) == 0x0d && buffer(pos+1) == 0x0a){ // found a Line
                pos += 2
                Some(Line(begin,pos-1))
            }
            else None
        }

        def parseHeaders(): Option[Map[String, String]] = {
            val headers = collection.mutable.Map[String, String]()

            var line: Option[Line] = None
            var endOfHeader = false
            do {
                line = nextLine()
                line match {
                    case Some(headerLine) if headerLine.eolPos == headerLine.startPos + 1 => // Empty
                        endOfHeader = true
                    case Some(headerLine) => // match a name: value
                        val str = new String(buffer, headerLine.startPos, headerLine.eolPos - headerLine.startPos - 1)
                        str match {
                            case HEADER_PATTERN(name, value) =>
                                // TODO Header Name ignore Case
                                if(name.equalsIgnoreCase("Content-Length"))
                                    headers("Content-Length") = value
                                else
                                    headers(name) = value
                            case _ =>
                                assert(false, s"expect a header, but $str")
                        }
                    case None =>    // not got a Line, NOOP
                }
            } while(endOfHeader == false || line == None)

            if(endOfHeader)
                Some(headers.toMap)
            else None
        }

        def parseBody(headers: Map[String, String]): Option[ByteBuffer] = {
            headers.get("Content-Length") match {
                case Some(lengthStr) =>
                    if(pos + lengthStr.toInt == buffer.length) {
                        Some(new ByteBuffer(buffer, pos, lengthStr.toInt))
                    }
                    else None // TODO <, >
                case None =>
                    // TODO process No Content-Length, act as Content-Length = 0
                    Some(new ByteBuffer(buffer, pos, buffer.length - pos) )
                //                        if(stream.status == TcpOnewayStream.S_FIN) {
                //                            Some(new ByteBuffer(string, pos, string.length - pos))
                //                        }
                //                        else None
            }
        }

        def parse(): Option[HttpEvent] = {

            nextLine() match {
                case Some(firstLine) if firstLinePattern.matches( firstLine.asStr(buffer) ) =>

                    val result =
                        for( headers <- parseHeaders();
                             data <- parseBody(headers))
                            yield parseEvent(firstLine.asStr(buffer), headers, data)

                    result match {
                        case Some(event) => result
                        case None => Some(partial()) //  TODO
                    }
                case None => None // Not a HttpEvent

            }

        }

        def partial(): HttpEvent

        def parseEvent(line0: String, headers: Map[String, String], data: Packet.ByteBuffer) : HttpEvent

    }
    class RequestParser(stream:TcpOnewayStream, bytes: Array[Byte]) extends Parser(stream, REQ_LINE1_PATTERN, bytes) {

        override def parseEvent(line0: String, headers: Map[String, String], data: ByteBuffer) = {
            line0 match {
                case REQ_LINE1_PATTERN(method, url, version) =>
                    HttpRequest(
                        srcIP =  stream.srcIP,
                        srcPort = stream.srcPort,
                        destIP = stream.destIP,
                        destPort = stream.destPort,
                        ts = stream.lastPacketTs.get,
                        method = method,
                        url = url,
                        version = version,
                        headers = headers,
                        data = data
                    )
                case _ =>
                    throw new AssertionError(s"expect ${REQ_LINE1_PATTERN} but $line0")
            }
        }

        override def partial(): HttpEvent = HttpRequestPartial()
    }

    class ResponseParser(stream: TcpOnewayStream, bytes: Array[Byte]) extends Parser(stream, RESP_LINE1_PATTERN, bytes) {
        override def parseEvent(line0: String, headers: Map[String, String], data: ByteBuffer): HttpEvent = {
            line0 match {
                case RESP_LINE1_PATTERN(version, code, message) =>
                    HttpResponse(
                        srcIP =  stream.srcIP,
                        srcPort = stream.srcPort,
                        destIP = stream.destIP,
                        destPort = stream.destPort,
                        ts = stream.lastPacketTs.get,
                        version = version,
                        code = code.toInt,
                        message = message,
                        headers = headers,
                        data = data
                    )
                case _ =>
                    throw new AssertionError(s"expect ${REQ_LINE1_PATTERN} but $line0")
            }
        }

        override def partial(): HttpEvent = HttpResponsePartial()
    }

}
