#pragma once

#include <cstdint>
#include <string>

struct Ip final {
	static const int SIZE = 4;

	Ip() {}
	Ip(const uint32_t r) : ip_(r) {}
	Ip(const std::string r);

	operator uint32_t() const { return ip_; }
	explicit operator std::string() const;

	bool operator == (const Ip& r) const { return ip_ == r.ip_; }

protected:
	uint32_t ip_;
};

