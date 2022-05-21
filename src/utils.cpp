#include "utils.h"
#include "pppoe.h"

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

vector<uint8_t> extractHostUniq(uint8_t *data, uint16_t len)
{
    uint8_t index = 0;
    for (; index < len; ++index)
    {
        if (data[index] == 0x01 && data[index + 1] == 0x03)
        {
            break;
        }
    }
    if (index == len)
    {
        Serial.println("No Host Uniq found");
        return vector<uint8_t>();
    }
    auto res = vector<uint8_t>();
    uint16_t hostUniqLen = data[index + 2] << 8 | data[index + 3];
    for (uint16_t i = 0; i < hostUniqLen + 4; ++i)
    {
        Serial.print(data[index + i], HEX);
        res.push_back(data[index + i]);
    }
    return res;
}

void fillDeviceMAC(array<uint8_t, 6> &addr)
{
    addr[0] = MAC_ADDRESS[0];
    addr[1] = MAC_ADDRESS[1];
    addr[2] = MAC_ADDRESS[2];
    addr[3] = MAC_ADDRESS[3];
    addr[4] = MAC_ADDRESS[4];
    addr[5] = MAC_ADDRESS[5];
}