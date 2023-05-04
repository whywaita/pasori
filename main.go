//go:build !windows

package pasori

import (
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/google/gousb"
)

type packet struct {
	inep  *gousb.InEndpoint
	outep *gousb.OutEndpoint
}

const (
	InSetRf       = 0x00
	InSetProtocol = 0x02
	InCommRf      = 0x04
)

func (p *packet) checksum(cmd byte, buf []byte) byte {
	for _, b := range buf {
		cmd += b
	}
	return ^cmd + 1
}

func (p *packet) send(buf []byte) ([]byte, error) {
	_, err := p.outep.Write(buf)
	if err != nil {
		return nil, err
	}

	rcv := make([]byte, 255)
	_, err = p.inep.Read(rcv)
	if err != nil {
		return nil, err
	}

	rbuf := make([]byte, 255)
	_, err = p.inep.Read(rbuf)
	if err != nil {
		return nil, err
	}
	return rbuf, nil
}

func (p *packet) write(buf []byte) ([]byte, error) {
	n := len(buf)
	cmd := []byte{0x00, 0x00, 0xff, 0xff, 0xff}
	cmd = append(cmd, byte(n+1))
	cmd = append(cmd, byte(((n+1)&0xff00)>>8))
	cmd = append(cmd, p.checksum(0x00, cmd[5:7]))
	cmd = append(cmd, 0xd6)
	cmd = append(cmd, buf...)
	cmd = append(cmd, p.checksum(0xd6, buf))
	cmd = append(cmd, 0x00)
	return p.send(cmd)
}

func (p *packet) init() error {
	cmd := []byte{0x00, 0x00, 0xff, 0x00, 0xff, 0x00}
	_, err := p.outep.Write(cmd)
	if err != nil {
		return err
	}
	return nil
}

func (p *packet) setCommandType() ([]byte, error) {
	cmd := []byte{0x2A, 0x01}
	return p.write(cmd)
}

func (p *packet) switchRF() ([]byte, error) {
	cmd := []byte{0x06, 0x00}
	return p.write(cmd)
}

// inSetRF set a bitrate of RF communication
func (p *packet) inSetRF(nfcType NFCType) ([]byte, error) {
	var cmd []byte
	switch nfcType {
	case NFCTypeF:
		cmd = []byte{InSetRf, 0x01, 0x01, 0x0f, 0x01} // 212F
	case NFCTypeA:
		cmd = []byte{InSetRf, 0x02, 0x03, 0x0f, 0x03} // 106A
	case NFCTypeB:
		cmd = []byte{InSetRf, 0x03, 0x07, 0x0f, 0x07} // 106B
	}
	return p.write(cmd)
}

func (p *packet) inSetProtocol1() ([]byte, error) {
	cmd := []byte{InSetProtocol, 0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08, 0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x06}
	return p.write(cmd)
}

func (p *packet) inSetProtocol2(nfcType NFCType) ([]byte, error) {
	var cmd []byte
	switch nfcType {
	case NFCTypeF:
		cmd = []byte{InSetProtocol, 0x00, 0x18}
	case NFCTypeA:
		return p.inSetProtocol(map[string]int{
			"initial_guard_time":  6,
			"add_crc":             0,
			"check_crc":           0,
			"check_parity":        1,
			"last_byte_bit_count": 7,
		})
	case NFCTypeB:
		cmd = []byte{InSetProtocol, 0x00, 0x14, 0x09, 0x01, 0x0a, 0x01, 0x0b, 0x01, 0x0c, 0x01}
	}
	return p.write(cmd)
}

func (p *packet) sensReq(nfcType NFCType) ([]byte, error) {
	var cmd []byte
	switch nfcType {
	case NFCTypeF:
		cmd = []byte{InCommRf, 0x6e, 0x00, 0x06, 0x00, 0xff, 0xff, 0x01, 0x00}
	case NFCTypeA:
		cmd = []byte{InCommRf, 0x36, 0x01, 0x26}
	case NFCTypeB:
		cmd = []byte{InCommRf, 0x6e, 0x00, 0x05, 0x00, 0x10}
	}

	return p.write(cmd)
}

func (p *packet) parse(buf []byte) []byte {
	return buf[9:]
}

func newPacket(ctx *gousb.Context, dev *gousb.Device) (*packet, error) {
	intf, done, err := dev.DefaultInterface()
	if err != nil {
		return nil, err
	}
	defer done()

	var in *gousb.InEndpoint
	var out *gousb.OutEndpoint

	for _, v := range intf.Setting.Endpoints {
		if v.Direction == gousb.EndpointDirectionIn && in == nil {
			in, err = intf.InEndpoint(v.Number)
			if err != nil {
				return nil, err
			}
		}

		if v.Direction == gousb.EndpointDirectionOut && out == nil {
			out, err = intf.OutEndpoint(v.Number)
			if err != nil {
				return nil, err
			}
		}

		if in != nil && out != nil {
			break
		}
	}

	return &packet{
		inep:  in,
		outep: out,
	}, nil
}

func GetID(vid, pid uint16) ([]byte, error) {
	return GetIDWithType(vid, pid, NFCTypeF)
}

func GetIDWithType(vid, pid uint16, in NFCType) ([]byte, error) {
	ctx := gousb.NewContext()
	defer ctx.Close()

	dev, err := ctx.OpenDeviceWithVIDPID(gousb.ID(vid), gousb.ID(pid))
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	return GetIDByDevice(ctx, dev, in)
}

type NFCType int

const (
	NFCTypeUnknown NFCType = iota
	NFCTypeA
	NFCTypeB
	NFCTypeF
)

func (t NFCType) String() string {
	switch t {
	case NFCTypeA:
		return "A"
	case NFCTypeB:
		return "B"
	case NFCTypeF:
		return "F"
	default:
		return "Unknown"
	}
}

func UnmarshalNFCType(in any) NFCType {
	switch v := in.(type) {
	case string:
		return UnmarshalNFCTypeString(v)
	case NFCType:
		return in.(NFCType)
	default:
		return NFCTypeUnknown
	}
}

func UnmarshalNFCTypeString(in string) NFCType {
	switch in {
	case "A":
		return NFCTypeA
	case "B":
		return NFCTypeB
	case "F":
		return NFCTypeF
	default:
		return NFCTypeUnknown
	}
}

func GetIDByDevice(ctx *gousb.Context, dev *gousb.Device, nfcType NFCType) ([]byte, error) {
	if nfcType == NFCTypeUnknown {
		return nil, errors.New("unknown nfc type")
	}

	p, err := newPacket(ctx, dev)
	if err != nil {
		return nil, err
	}

	err = p.init()
	if err != nil {
		return nil, err
	}

	_, err = p.setCommandType()
	if err != nil {
		return nil, err
	}

	_, err = p.switchRF()
	if err != nil {
		return nil, err
	}

	_, err = p.inSetRF(nfcType)
	if err != nil {
		return nil, err
	}

	_, err = p.inSetProtocol1()
	if err != nil {
		return nil, err
	}

	_, err = p.inSetProtocol2(nfcType)
	if err != nil {
		return nil, err
	}

	isloop := true
	for isloop {
		rbuf, err := p.sensReq(nfcType)
		if err != nil {
			return nil, err
		}

		if rbuf[9] == 0x05 && rbuf[10] == 0x00 {
			rbuf := p.parse(rbuf)

			if rbuf[6] == 0x14 && rbuf[7] == 0x01 {
				// type-f
				idm := rbuf[8 : 8+8]
				// pmm := rbuf[16 : 16+8]
				return idm, nil
			}

			if rbuf[6] == 0x50 {
				// type-b
				nfcid := rbuf[7 : 7+4]
				// appdata := rbuf[11 : 11+4]
				// pinfo := rbuf[15 : 15+4]

				// fmt.Printf(" NFCID: %v\n", nfcid)
				// fmt.Printf(" Application Data: %v\n", appdata)
				// fmt.Printf(" Protocol Info: %v\n", pinfo)
				return nfcid, nil
			}

			if rbuf[6] == 0x44 {
				// type-a
				uid, err := p.getTypeAUID()
				if err != nil {
					return nil, fmt.Errorf("p.getTypeAUID(): %w", err)
				}
				return uid, nil
			}

			isloop = false
		}
		time.Sleep(1 * time.Millisecond)
	}
	return nil, errors.New("ID not found")
}

func (p *packet) getTypeAUID() ([]byte, error) {
	if _, err := p.inSetProtocol(map[string]int{
		"last_byte_bit_count": 8,
		"add_parity":          1,
	}); err != nil {
		return nil, err
	}

	if _, err := p.inSetProtocol(map[string]int{
		"add_crc":   1,
		"check_crc": 1,
	}); err != nil {
		return nil, err
	}

	uid := make([]byte, 0)
	for _, selCmd := range []byte{0x93, 0x95, 0x97} {
		if _, err := p.inSetProtocol(map[string]int{
			"add_crc":   0,
			"check_crc": 0,
		}); err != nil {
			return nil, err
		}

		sddReq := []byte{selCmd, 0x20}
		sddRes, err := p.inCommRf(sddReq)
		if err != nil {
			return nil, err
		}
		sddRes = sddRes[13 : 13+5]
		if _, err := p.inSetProtocol(map[string]int{
			"add_crc":   1,
			"check_crc": 1,
		}); err != nil {
			return nil, err
		}

		selReq := []byte{selCmd, 0x70}
		selReq = append(selReq, sddRes...)

		selRes, err := p.inCommRf(selReq)
		if err != nil {
			return nil, err
		}
		selRes = []byte{selRes[13]}

		if selRes[0]&0b00000100 != 0 {
			uid = append(uid, sddRes[1:4]...)
		} else {
			uid = append(uid, sddRes[0:4]...)
			break
		}
	}

	return uid, nil
}

func (p *packet) inCommRf(data []byte) ([]byte, error) {
	cmd := []byte{InCommRf, 0x36, 0x01}
	cmd = append(cmd, data...)

	b, err := p.write(cmd)
	if err != nil {
		return nil, err
	}

	if !(b[0] == 0x00 && b[1] == 0x00) {
		// CommunicationError
		return nil, fmt.Errorf("CommunicationError")
	}
	return b[2:], nil
}

func (p *packet) inSetProtocol(kwargs map[string]int) ([]byte, error) {
	data := inSetProtocol(kwargs)
	cmd := []byte{InSetProtocol}
	cmd = append(cmd, data...)

	return p.write(cmd)
}

func inSetProtocol(kwargs map[string]int) []byte {
	data := make([]byte, 0)

	keys := []string{"initial_guard_time", "add_crc", "check_crc", "multi_card",
		"add_parity", "check_parity", "bitwise_anticoll",
		"last_byte_bit_count", "mifare_crypto", "add_sof",
		"check_sof", "add_eof", "check_eof", "rfu", "deaf_time",
		"continuous_receive_mode", "min_len_for_crm",
		"type_1_tag_rrdd", "rfca", "guard_time"}
	sortedKeys := make([]string, 0, len(kwargs))
	for k := range kwargs {
		sortedKeys = append(sortedKeys, k)
	}
	sort.Strings(sortedKeys)
	for _, key := range sortedKeys {
		value := kwargs[key]
		index := indexOf(keys, key)
		data = append(data, byte(index), byte(value))
	}

	return data
}
func indexOf(array []string, value string) int {
	for i, v := range array {
		if v == value {
			return i
		}
	}
	return -1
}
