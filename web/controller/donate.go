package controller

// DonateEntry is one crypto address the project accepts donations on.
type DonateEntry struct {
	// Chain is the ticker + network as the README writes it ("USDT-TRC20").
	Chain string
	// Address is the receiving address, shown verbatim and copied verbatim.
	Address string
}

// donateAddresses mirrors the "## Donate" section of README.md, in the same
// order. It is duplicated rather than parsed because README.md sits outside
// this package and go:embed cannot reach a parent directory — so the copy is
// pinned by TestDonateAddressesMatchReadme, which fails the build if the two
// ever drift. Edit the README and this list together; the test names the diff.
var donateAddresses = []DonateEntry{
	{"USDC-Polygon", "0xdC2Ab962954e8fA1502C44656c5A32CF2979568C"},
	{"USDT-BEP20", "0xdC2Ab962954e8fA1502C44656c5A32CF2979568C"},
	{"USDT-TRC20", "TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR"},
	{"TRX", "TXEhckDXtdLGAjP5PZXfNnQjPHzEVTcBmR"},
	{"LTC", "ltc1qmapmnuf6cq9x679nmu0k4uyq779mxxcwnkgdll"},
	{"BTC", "bc1q62w7lyndzndsp74vj4dsayvun8xnapzq6hx5ea"},
	{"ETH", "0xdC2Ab962954e8fA1502C44656c5A32CF2979568C"},
}
