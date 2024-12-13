#include "UdpParsing.h"
#include <iostream>
#include <map>
#include <vector>

#include <sick_visionary_cpp_base/ITransport.h>
#include <sick_visionary_cpp_base/VisionaryEndian.h>

namespace visionary {
ITransport::ByteBuffer reassembleFragments(const std::map<std::uint16_t, ITransport::ByteBuffer>& fragmentMap)
{
  ITransport::ByteBuffer completeBlob;
  for (std::map<std::uint16_t, ITransport::ByteBuffer>::const_iterator it = fragmentMap.begin();
       it != fragmentMap.end();
       ++it)
  {
    completeBlob.insert(completeBlob.end(), it->second.begin(), it->second.end());
  }
  std::cout << "Reassembled frame from fragments\n" << "\n";
  return completeBlob;
}

bool parseSegmBinaryData(std::vector<std::uint8_t>::iterator itBuf,
                         std::size_t                         bufferSize,
                         std::shared_ptr<VisionaryData>      m_dataHandler)
{
  if (m_dataHandler == nullptr)
  {
    std::cout << "No datahandler is set -> cant parse blob data" << "\n";
    return false;
  }
  bool result               = false;
  using ItBufDifferenceType = std::vector<std::uint8_t>::iterator::difference_type;
  auto itBufSegment         = itBuf;
  auto remainingSize        = bufferSize;

  if (remainingSize < 4)
  {
    std::cout << "Received not enough data to parse segment description. Connection issues?" << "\n";
    return false;
  }

  //-----------------------------------------------
  // Extract informations in Segment-Binary-Data
  // const std::uint16_t blobID = readUnalignBigEndian<std::uint16_t>(&*itBufSegment);
  itBufSegment += sizeof(std::uint16_t);
  const auto numSegments = readUnalignBigEndian<std::uint16_t>(&*itBufSegment);
  itBufSegment += sizeof(std::uint16_t);
  remainingSize -= 4;

  // offset and changedCounter, 4 bytes each per segment
  std::vector<std::uint32_t> offset(numSegments);
  std::vector<std::uint32_t> changeCounter(numSegments);
  const std::uint16_t        segmentDescriptionSize = 4u + 4u;
  const std::size_t totalSegmentDescriptionSize     = static_cast<std::size_t>(numSegments * segmentDescriptionSize);
  if (remainingSize < totalSegmentDescriptionSize)
  {
    std::cout << "Received not enough data to parse segment description. Connection issues?" << "\n";
    return false;
  }
  if (numSegments < 3)
  {
    std::cout << "Invalid number of segments. Connection issues?" << "\n";
    return false;
  }
  for (std::uint16_t i = 0; i < numSegments; i++)
  {
    offset[i] = readUnalignBigEndian<std::uint32_t>(&*itBufSegment);
    itBufSegment += sizeof(std::uint32_t);
    changeCounter[i] = readUnalignBigEndian<std::uint32_t>(&*itBufSegment);
    itBufSegment += sizeof(std::uint32_t);
  }
  remainingSize -= totalSegmentDescriptionSize;

  //-----------------------------------------------
  // First segment contains the XML Metadata
  const std::size_t xmlSize = (offset[1]) - offset[0];

  if (remainingSize < xmlSize)
  {
    std::cout << "Received not enough data to parse xml Description. Connection issues?" << "\n";
    return false;
  }
  remainingSize -= xmlSize;
  const std::string xmlSegment((itBuf + static_cast<ItBufDifferenceType>(offset[0])),
                               (itBuf + static_cast<ItBufDifferenceType>(offset[1])));

  if (m_dataHandler->parseXML(xmlSegment, changeCounter[0]))
  {
    //-----------------------------------------------
    // Second segment contains Binary data
    std::size_t binarySegmentSize = offset[2] - (offset[1]);

    if (remainingSize < binarySegmentSize)
    {
      std::cout << "Received not enough data to parse binary Segment. Connection issues?" << "\n";
      return false;
    }
    result = m_dataHandler->parseBinaryData((itBuf + static_cast<ItBufDifferenceType>(offset[1])), binarySegmentSize);
    remainingSize -= binarySegmentSize;
  }
  return result;
}

bool parseUdpBlob(std::vector<std::uint8_t> buffer, std::shared_ptr<VisionaryData> m_dataHandler)
{
  const auto packageLength = readUnalignBigEndian<std::uint32_t>(buffer.data() + 4);

  if (packageLength < 3u)
  {
    std::cout << "Invalid package length " << packageLength << ". Should be at least 3" << "\n";
    return false;
  }

  // Check that protocol version and packet type are correct
  const auto protocolVersion = readUnalignBigEndian<std::uint16_t>(buffer.data() + 8);
  const auto packetType      = readUnalignBigEndian<std::uint8_t>(buffer.data() + 10);
  if (protocolVersion != 0x001)
  {
    std::cout << "Received unknown protocol version " << protocolVersion << "." << "\n";
    return false;
  }
  if (packetType != 0x62)
  {
    std::cout << "Received unknown packet type " << packetType << "." << "\n";
    return false;
  }

  return parseSegmBinaryData(buffer.begin() + 11, buffer.size() - 3u, m_dataHandler);
}

} // namespace visionary
