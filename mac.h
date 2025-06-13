#pragma once

#include <cstdint>
#include <cstring>
#include <string>

struct Mac final {
	static constexpr int SIZE = 6;

	Mac() {}
	Mac(const Mac& r) { memcpy(mac_, r.mac_, SIZE); }
	Mac(const uint8_t* r) { memcpy(mac_, r, SIZE); }
	Mac(const std::string& r);

	Mac& operator = (const Mac& r) { memcpy(mac_, r.mac_, SIZE); return *this; }

	explicit operator uint8_t*() const { return const_cast<uint8_t*>(mac_); }
	explicit operator std::string() const;

	bool operator == (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) == 0; }
	bool operator < (const Mac& r) const { return memcmp(mac_, r.mac_, SIZE) < 0; }

	bool isNull() const { return *this == nullMac(); }
	bool isBroadcast() const { return *this == broadcastMac(); }

	static Mac& nullMac();
	static Mac& broadcastMac();

protected:
	uint8_t mac_[SIZE];
};

namespace std {
	template<>
	struct hash<Mac> {
		size_t operator()(const Mac& r) const {
			return std::_Hash_impl::hash(&r, Mac::SIZE);
		}
	};
}

