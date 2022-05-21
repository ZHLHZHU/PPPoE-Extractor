#include <Arduino.h>
#include <vector>
#include <array>

using namespace std;

void printPaddedHex(uint8_t byte);

void printMACAddress(const uint8_t address[6]);

vector<uint8_t> extractHostUniq(uint8_t *data, uint16_t len);

void fillDeviceMAC(array<uint8_t, 6> &addr);