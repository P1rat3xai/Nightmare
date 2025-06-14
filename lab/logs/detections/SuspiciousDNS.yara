rule SuspiciousDNSFailure
{
  meta:
    description = "Repeated failure to resolve www.msftncsi.com"
    author = "Q / AP3X"
    reference = "Event ID 1014 DNS Client"
  condition:
    uint16(0) == 0x1014 and
    "msftncsi.com" ascii
}
