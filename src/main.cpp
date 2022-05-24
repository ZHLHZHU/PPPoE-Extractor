#include "w5500.h"
#include "pppoe.h"
#include "utils.h"

using namespace std;

Wiznet5500 w5500;
uint8_t readBuffer[1518];
uint8_t writeBuffer[1518];
uint16_t sessionId = 0x0000;
bool flag = false;

class PPPoETag {
public:
    PPPoETag() = default;

    PPPoETag(uint8_t const *buf, uint16_t len) {
        tagType = buf[0] << 8 | buf[1];
        for (uint16_t i = 4; i < len; i++) {
            tagData.push_back(buf[i]);
        }
    }

    uint16_t tagType{};
    vector<uint8_t> tagData;

    uint16_t size() const {
        return 4 + tagData.size();
    }
};

class PPPOption {
public:
    uint8_t type{};
    vector<uint8_t> data;

    PPPOption() = default;

    uint16_t size() const {
        return 2 + data.size();
    }
};

class Ethernet {
public:
    array<uint8_t, 6> srcMac;
    array<uint8_t, 6> dstMac;
    uint16_t ethType;
};

class PPPoE : public Ethernet {
public:
    uint8_t ver;
    uint8_t type;
    uint8_t code;
    uint16_t sessionId;
    uint16_t payloadLen;
};

class PPPoEDiscovery : public PPPoE {
public:
    vector<PPPoETag> tags;

    PPPoEDiscovery() : PPPoE() {}

    PPPoEDiscovery(uint8_t *buf, uint16_t ethFrameLen) : PPPoE() {
        dstMac = {buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]};
        srcMac = {buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]};
        ethType = (buf[12] << 8) + buf[13];
        ver = buf[14] >> 4 != 0;
        type = buf[14] & 0x0F;
        code = buf[15];
        sessionId = (buf[16] << 8) + buf[17];
        payloadLen = (buf[18] << 8) + buf[19];
        for (int i = 20; i < 20 + payloadLen;) {
            PPPoETag tag;
            tag.tagType = (buf[i] << 8) + buf[i + 1];
            uint16_t tagLen = (buf[i + 2] << 8) + buf[i + 3];
            for (int j = 0; j < tagLen; j++) {
                tag.tagData.push_back(buf[i + 4 + j]);
            }
            tags.push_back(tag);
            i += 4 + tagLen;
        }
    }

    PPPoETag getHostUniqTag() {
        for (auto tag: tags) {
            if (tag.tagType == 0x0103) {
                return tag;
            }
        }
        return {};
    }

    uint16_t size() {
        uint16_t res = 20;
        for (auto &tag: tags) {
            res += tag.size();
        }
        return res;
    }

    PPPoEDiscovery clone() {
        PPPoEDiscovery req;
        req.srcMac = srcMac;
        req.dstMac = dstMac;
        req.ethType = ethType;
        req.ver = ver;
        req.type = type;
        req.code = code;
        req.sessionId = sessionId;
        req.payloadLen = payloadLen;
        for (const auto &tag: tags) {
            PPPoETag newTag;
            newTag.tagType = tag.tagType;
            for (auto data: tag.tagData) {
                newTag.tagData.push_back(data);
            }
            req.tags.push_back(newTag);
        }
        return req;
    }

    vector<uint8_t> toBytes() {
        vector<uint8_t> buf;
        buf.insert(buf.end(), dstMac.begin(), dstMac.end());
        buf.insert(buf.end(), srcMac.begin(), srcMac.end());
        buf.push_back(ethType >> 8);
        buf.push_back(ethType & 0xFF);
        buf.push_back(ver << 4 | type);
        buf.push_back(code);
        buf.push_back(sessionId >> 8);
        buf.push_back(sessionId & 0xFF);

        uint16_t tagsSize = 0;
        for (const auto& tag: tags) {
            tagsSize += tag.size();
        }

        buf.push_back(tagsSize >> 8);
        buf.push_back(tagsSize & 0xFF);
        for (const auto &tag: tags) {
            buf.push_back(tag.tagType >> 8);
            buf.push_back(tag.tagType & 0xFF);
            buf.push_back(tag.tagData.size() >> 8);
            buf.push_back(tag.tagData.size() & 0xFF);
            for (auto data: tag.tagData) {
                buf.push_back(data);
            }
        }
        return buf;
    }

    String toString() {
        String str;
        str += "ver: " + String(ver) + "\n";
        str += "type: " + String(type) + "\n";
        str += "code: " + String(code) + "\n";
        str += "sessionId: " + String(sessionId, HEX) + "\n";
        str += "payloadLen: " + String(payloadLen) + "\n";
        for (const auto &tag: tags) {
            str += "tagType: " + String(tag.tagType, HEX) + "\n";
            str += "tagData: ";
            for (auto data: tag.tagData) {
                str += String(data, HEX) + " ";
            }
            str += "\n";
        }
        return str;
    }
};

class PPPoESession : public PPPoE {
public:
    uint16_t protocol{};
    uint8_t pppCode{};
    uint8_t pppIdentifier{};
    // ppp length indicate the length of ppp link control protocol
    uint16_t pppLength{};

    vector<PPPOption> options;

    PPPoESession() : PPPoE() {}

    PPPoESession(uint8_t *buf, uint16_t ethFrameLen) : PPPoE() {
        dstMac = {buf[0], buf[1], buf[2], buf[3], buf[4], buf[5]};
        srcMac = {buf[6], buf[7], buf[8], buf[9], buf[10], buf[11]};
        ethType = (buf[12] << 8) + buf[13];
        ver = buf[14] >> 4 != 0;
        type = buf[14] & 0x0F;
        code = buf[15];
        sessionId = (buf[16] << 8) + buf[17];
        payloadLen = (buf[18] << 8) + buf[19];
        protocol = (buf[20] << 8) + buf[21];
        pppCode = buf[22];
        pppIdentifier = buf[23];
        pppLength = (buf[24] << 8) + buf[25];
        for (int i = 26; i < 26 + pppLength - 4;) {
            PPPOption option;
            option.type = buf[i];
            uint8_t optionLen = buf[i + 1];
            for (int j = 2; j < optionLen; j++) {
                option.data.push_back(buf[i + j]);
            }
            options.push_back(option);
            i += optionLen;
        }
    }

    PPPoESession clone() {
        PPPoESession req;
        req.srcMac = srcMac;
        req.dstMac = dstMac;
        req.ethType = ethType;
        req.ver = ver;
        req.type = type;
        req.code = code;
        req.sessionId = sessionId;
        req.payloadLen = payloadLen;
        req.protocol = protocol;
        req.pppCode = pppCode;
        req.pppIdentifier = pppIdentifier;
        req.pppLength = pppLength;
        for (const auto &option: options) {
            PPPOption newOption;
            newOption.type = option.type;
            for (auto data: option.data) {
                newOption.data.push_back(data);
            }
            req.options.push_back(newOption);
        }
        return req;
    }

    vector<uint8_t> toBytes() {
        vector<uint8_t> buf;
        buf.insert(buf.end(), dstMac.begin(), dstMac.end());
        buf.insert(buf.end(), srcMac.begin(), srcMac.end());
        buf.push_back(ethType >> 8);
        buf.push_back(ethType & 0xFF);
        buf.push_back(ver << 4 | type);
        buf.push_back(code);
        buf.push_back(sessionId >> 8);
        buf.push_back(sessionId & 0xFF);

        uint16_t payloadSize = 6;
        for (const auto &opt: options) {
            payloadSize += opt.size();
        }
        buf.push_back(payloadSize >> 8);
        buf.push_back(payloadSize & 0xFF);
        buf.push_back(protocol >> 8);
        buf.push_back(protocol & 0xFF);
        buf.push_back(pppCode);
        buf.push_back(pppIdentifier);
        uint16_t optSize = 4;
        for (const auto& opt: options) {
            optSize += opt.size();
        }
        buf.push_back(optSize >> 8);
        buf.push_back(optSize & 0xFF);
        for (const auto &opt: options) {
            buf.push_back(opt.type);
            buf.push_back(opt.data.size() + 2);
            for (auto data: opt.data) {
                buf.push_back(data);
            }
        }

        return buf;
    }

    uint16_t size() {
        uint16_t res = 26;
        for (auto &option: options) {
            res += option.size();
        }
        return res;
    }

    String toString() {
        String str;
        str += "ver: " + String(ver) + "\n";
        str += "type: " + String(type) + "\n";
        str += "code: " + String(code) + "\n";
        str += "sessionId: " + String(sessionId, HEX) + "\n";
        str += "payloadLen: " + String(payloadLen) + "\n";
        str += "protocol: " + String(protocol, HEX) + "\n";
        str += "pppCode: " + String(pppCode, HEX) + "\n";
        str += "pppIdentifier: " + String(pppIdentifier, HEX) + "\n";
        str += "pppLength: " + String(pppLength, HEX) + "\n";
        for (const auto &option: options) {
            str += "optionType: " + String(option.type, HEX) + "\n";
            str += "optionData: ";
            for (auto data: option.data) {
                str += String(data, HEX) + " ";
            }
            str += "\n";
        }
        return str;
    }
};

void sendCfgReject(PPPoESession req) {
    auto res = req.clone();
    res.dstMac = req.srcMac;
    fillDeviceMAC(res.srcMac);
    res.pppCode = 0x04;
    w5500.sendFrame(&res.toBytes()[0], res.size());
}

void sendDeviceOpt(PPPoESession req) {
    auto res = req.clone();
    res.dstMac = req.srcMac;
    fillDeviceMAC(res.srcMac);
    res.options.clear();
    PPPOption maxRecUnit;
    maxRecUnit.type = 0x01;
    maxRecUnit.data.push_back(0x05);
    maxRecUnit.data.push_back(0xc8);

    PPPOption magicNum;
    magicNum.type = 0x05;
    magicNum.data.push_back(0x10);
    magicNum.data.push_back(0x25);
    magicNum.data.push_back(0x16);
    magicNum.data.push_back(0x52);
    res.options.push_back(maxRecUnit);
    res.options.push_back(magicNum);
    w5500.sendFrame(&res.toBytes()[0], res.size());
}

void handlePADI(PPPoEDiscovery req) {
    // response PADO
    auto res = req.clone();
    res.dstMac = req.srcMac;
    fillDeviceMAC(res.srcMac);
    res.code = 0x07;
    PPPoETag anyService(ANY_SERVICE_TAG, sizeof(ANY_SERVICE_TAG));
    PPPoETag acName(AC_NAME, sizeof(AC_NAME));
    PPPoETag hostuniq = req.getHostUniqTag();
    res.tags.clear();
    res.tags.push_back(anyService);
    res.tags.push_back(acName);
    if (hostuniq.tagType != 0x00) {
        res.tags.push_back(hostuniq);
    }
    w5500.sendFrame(&res.toBytes()[0], res.size());
}

void handlePADR(PPPoEDiscovery req) {
    // response PADS
    auto res = req.clone();
    res.dstMac = req.srcMac;
    fillDeviceMAC(res.srcMac);
    res.code = 0x65;
    res.sessionId = random(1025);
    PPPoETag anyService(ANY_SERVICE_TAG, sizeof(ANY_SERVICE_TAG));
    PPPoETag acName(AC_NAME, sizeof(AC_NAME));
    PPPoETag hostuniq = req.getHostUniqTag();
    res.tags.clear();
    res.tags.push_back(anyService);
    res.tags.push_back(acName);
    if (hostuniq.tagType != 0x00) {
        res.tags.push_back(hostuniq);
    }
    w5500.sendFrame(&res.toBytes()[0], res.size());
}

void handleCfgReq(PPPoESession req) {
    // 直接拒绝
    if (!flag) {
        sendCfgReject(req);
        flag = true;
        sendDeviceOpt(req);
        return;
    }
    auto res = req.clone();
    res.dstMac = req.srcMac;
    fillDeviceMAC(res.srcMac);
    res.pppCode = 0x02;
    Serial.println("res:");
    Serial.println(res.toString());
    w5500.sendFrame(&res.toBytes()[0], res.size());
}

void setup() {
    // Setup serial port for debugging
    Serial.begin(115200);
    randomSeed(analogRead(0));

    Serial.println("Starting...,MAC Address:");
    printMACAddress(MAC_ADDRESS);

    w5500.begin(MAC_ADDRESS);
}

void loop() {

    uint16_t len = w5500.readFrame(readBuffer, sizeof(readBuffer));
    if (len > 0) {
        auto *ethTypeLittle = (uint16_t *) &readBuffer[12];
        uint16_t ethType = *ethTypeLittle >> 8 | *ethTypeLittle << 8;
        if (ethType == 0x8863) {
            // Serial.println("PPPoE Discovery stage");
            PPPoEDiscovery req(readBuffer, len);
            if (req.code == 0x09) {
                handlePADI(req);
            }
            if (req.code == 0x19) {
                handlePADR(req);
            }
        }
        if (ethType == 0x8864) {
            // Serial.println("PPPoE Session stage");
            // parsePPPoEHeader(readBuffer + 14, len - 14);
            PPPoESession req(readBuffer, len);
            if (req.protocol == 0xc021 && req.pppCode == 0x01) {
                // Serial.println("PPP Configure Request");
                handleCfgReq(req);
            }
        }
    }
}
