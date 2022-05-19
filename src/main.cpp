#include "w5500.h"

const byte mac_address[] = {
    0x52, 0xff, 0xee, 0x1b, 0x44, 0x55};

Wiznet5500 w5500;
uint8_t readBuffer[1518];
uint8_t writeBuffer[1518];
uint8_t send_count = 0;

void printPaddedHex(uint8_t byte)
{
    char str[2];
    str[0] = (byte >> 4) & 0x0f;
    str[1] = byte & 0x0f;

    for (int i = 0; i < 2; i++)
    {
        // base for converting single digit numbers to ASCII is 48
        // base for 10-16 to become lower-case characters a-f is 87
        if (str[i] > 9)
            str[i] += 39;
        str[i] += 48;
        Serial.print(str[i]);
    }
}

void printMACAddress(const uint8_t address[6])
{
    for (uint8_t i = 0; i < 6; ++i)
    {
        printPaddedHex(address[i]);
        if (i < 5)
            Serial.print(':');
    }
    Serial.println();
}

void resPADO(byte *payload, uint16_t length)
{
    memcpy(&writeBuffer[0], &readBuffer[6], 6); // Set Destination to Source
    memcpy(&writeBuffer[6], mac_address, 6);    // Set Source to our MAC address
    writeBuffer[12] = 0x88;
    writeBuffer[13] = 0x63;
    writeBuffer[14] = 0x11;
    writeBuffer[15] = 0x07;
    writeBuffer[16] = 0x00;
    writeBuffer[17] = 0x00;
    writeBuffer[18] = 0x01;
    writeBuffer[19] = 0x20;
    byte resPayload[] = {0x01,0x01,0x00,0x00,0x01, 0x02, 0x00, 0x04, 0x5a, 0x48, 0x4c, 0x48, 0x01, 0x03, 0x00, 0x0c, 0x2F, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x2F, 0x00, 0x00, 0x00};
    
    memcpy(&writeBuffer[20], resPayload, sizeof(resPayload));

    uint16_t payload_len = sizeof(resPayload);
    writeBuffer[18] = payload_len >> 8 & 0xFF;
    writeBuffer[19] = payload_len & 0xFF;
    printMACAddress(writeBuffer);
    printMACAddress(writeBuffer + 6);
    w5500.sendFrame(writeBuffer, 18+payload_len);
}

void parsePPPoEHeader(void *payload, uint16_t len)
{
    uint8_t version = ((uint8_t *)payload)[0] & 0x0F;
    uint8_t type = ((uint8_t *)payload)[0] >> 4;
    Serial.printf("PPPoE Version=%d\n", version);
    Serial.printf("PPPoE Type=%d\n", type);

    uint8_t code = ((uint8_t *)payload)[1];
    Serial.printf("PPPoE Code=0x%02x\n", code);

    uint16_t sessionId = ((uint8_t *)payload)[2] << 8 | ((uint8_t *)payload)[3];
    uint16_t length = ((uint8_t *)payload)[4] << 8 | ((uint8_t *)payload)[5];
    Serial.printf("PPPoE SessionId=%d\n", sessionId);
    Serial.printf("PPPoE Length=%d\n", length);

    void *payloadPtr = (uint8_t *)payload + 6;
}

void setup()
{
    // Setup serial port for debugging
    Serial.begin(115200);
    Serial.println("[W5500MacRaw]");
    printMACAddress(mac_address);

    w5500.begin(mac_address);
}

void loop()
{

    uint16_t len = w5500.readFrame(readBuffer, sizeof(readBuffer));
    if (len > 0)
    {
        // Serial.print("Len=");
        // Serial.println(len, DEC);

        // Serial.print("Dest=");
        // printMACAddress(&buffer[0]);
        // Serial.print("Src=");
        // printMACAddress(&buffer[6]);

        // // 0x0800 = IPv4
        // // 0x0806 = ARP
        // // 0x86DD = IPv6
        // Serial.print("Type=0x");
        // printPaddedHex(buffer[12]);
        // printPaddedHex(buffer[13]);
        // Serial.println();

        // Reply to the 0x88B5 Local Experimental Ethertype
        // if (buffer[12] == 0x88 && buffer[13] == 0xB5) {
        //     Serial.print("Byte 15=");
        //     Serial.println(buffer[15], DEC);

        //     memcpy(&buffer[0], &buffer[6], 6);   // Set Destination to Source
        //     memcpy(&buffer[6], mac_address, 6);  // Set Source to our MAC address
        //     buffer[14] = send_count++;
        //     w5500.sendFrame(buffer, len);
        // }
        uint16_t *ethTypeLittle = (uint16_t *)&readBuffer[12];
        uint16_t ethType = *ethTypeLittle >> 8 | *ethTypeLittle << 8;
        if (ethType == 0x8863)
        {
            Serial.println(len);
            Serial.println("PPPoE Discovery stage");
            parsePPPoEHeader(readBuffer + 14, len - 14);
            Serial.println();
            resPADO(readBuffer, len);
        }
        if (ethType == 0x8864)
        {
            Serial.print("PPPoE Session stage");
        }
    }
}
