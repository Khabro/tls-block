#include "mac.h"
#include <cstdio>
#include <sstream>

Mac::Mac(const std::string& r) {
	std::string s;
	for (char ch : r) {
		if (isxdigit(ch)) s += ch;
	}
	int res = sscanf(s.c_str(), "%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
	                 &mac_[0], &mac_[1], &mac_[2], &mac_[3], &mac_[4], &mac_[5]);
	if (res != SIZE) {
		fprintf(stderr, "Mac::Mac sscanf return %d r=%s\n", res, r.c_str());
	}
}

Mac::operator std::string() const {
	char buf[20];
	sprintf(buf, "%02X:%02X:%02X:%02X:%02X:%02X",
	        mac_[0], mac_[1], mac_[2], mac_[3], mac_[4], mac_[5]);
	return std::string(buf);
}

Mac& Mac::nullMac() {
	static uint8_t zero[] = {0, 0, 0, 0, 0, 0};
	static Mac m(zero);
	return m;
}

Mac& Mac::broadcastMac() {
	static uint8_t ff[] = {255, 255, 255, 255, 255, 255};
	static Mac m(ff);
	return m;
}

