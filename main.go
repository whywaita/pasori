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

func (p *packet) setcommandtype() ([]byte, error) {
	cmd := []byte{0x2A, 0x01}
	return p.write(cmd)
}

func (p *packet) switch_rf() ([]byte, error) {
	cmd := []byte{0x06, 0x00}
	return p.write(cmd)
}

// inset_rf set a bitrate of RF communication
func (p *packet) inset_rf(nfc_type byte) ([]byte, error) {
	var cmd []byte
	switch nfc_type {
	case 'F':
		cmd = []byte{InSetRf, 0x01, 0x01, 0x0f, 0x01} // 212F
	case 'A':
		cmd = []byte{InSetRf, 0x02, 0x03, 0x0f, 0x03} // 106A
	case 'B':
		cmd = []byte{InSetRf, 0x03, 0x07, 0x0f, 0x07} // 106B
	}
	return p.write(cmd)
}

func (p *packet) inset_protocol_1() ([]byte, error) {
	cmd := []byte{InSetProtocol, 0x00, 0x18, 0x01, 0x01, 0x02, 0x01, 0x03, 0x00, 0x04, 0x00, 0x05, 0x00, 0x06, 0x00, 0x07, 0x08, 0x08, 0x00, 0x09, 0x00, 0x0a, 0x00, 0x0b, 0x00, 0x0c, 0x00, 0x0e, 0x04, 0x0f, 0x00, 0x10, 0x00, 0x11, 0x00, 0x12, 0x00, 0x13, 0x06}
	return p.write(cmd)
}

func (p *packet) inset_protocol_2(nfc_type byte) ([]byte, error) {
	var cmd []byte
	switch nfc_type {
	case 'F':
		cmd = []byte{InSetProtocol, 0x00, 0x18}
	case 'A':
		cmd = []byte{InSetProtocol, 0x01, 0x00, 0x02, 0x00, 0x05, 0x01, 0x00, 0x06, 0x07, 0x07}
	case 'B':
		cmd = []byte{InSetProtocol, 0x00, 0x14, 0x09, 0x01, 0x0a, 0x01, 0x0b, 0x01, 0x0c, 0x01}
	}
	return p.write(cmd)
}

func (p *packet) sens_req(nfc_type byte) ([]byte, error) {
	var cmd []byte
	switch nfc_type {
	case 'F':
		cmd = []byte{InCommRf, 0x6e, 0x00, 0x06, 0x00, 0xff, 0xff, 0x01, 0x00}
	case 'A':
		cmd = []byte{InCommRf, 0x36, 0x01, 0x26}
	case 'B':
		cmd = []byte{InCommRf, 0x6e, 0x00, 0x05, 0x00, 0x10}
	}

	return p.write(cmd)
}

func (p *packet) parse(buf []byte) []byte {
	return buf[9:len(buf)]
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
	ctx := gousb.NewContext()
	defer ctx.Close()

	dev, err := ctx.OpenDeviceWithVIDPID(gousb.ID(vid), gousb.ID(pid))
	if err != nil {
		return nil, err
	}
	defer dev.Close()

	return GetIDByDevice(ctx, dev)
}

func GetIDByDevice(ctx *gousb.Context, dev *gousb.Device) ([]byte, error) {
	p, err := newPacket(ctx, dev)
	if err != nil {
		return nil, err
	}

	err = p.init()
	if err != nil {
		return nil, err
	}

	_, err = p.setcommandtype()
	if err != nil {
		return nil, err
	}

	_, err = p.switch_rf()
	if err != nil {
		return nil, err
	}

	var nfc_type byte
	nfc_type = 'A'
	_, err = p.inset_rf(nfc_type)
	if err != nil {
		return nil, err
	}

	_, err = p.inset_protocol_1()
	if err != nil {
		return nil, err
	}

	_, err = p.inset_protocol_2(nfc_type)
	if err != nil {
		return nil, err
	}

	isloop := true
	for isloop {
		rbuf, err := p.sens_req(nfc_type)
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
	if _, err := p.inset_protocol(map[string]int{
		"last_byte_bit_count": 8,
		"add_parity":          1,
	}); err != nil {
		return nil, err
	}

	if _, err := p.inset_protocol(map[string]int{
		"add_crc":   1,
		"check_crc": 1,
	}); err != nil {
		return nil, err
	}

	uid := make([]byte, 0)
	for _, sel_cmd := range []byte{0x93, 0x95, 0x97} {
		if _, err := p.inset_protocol(map[string]int{
			"add_crc":   0,
			"check_crc": 0,
		}); err != nil {
			return nil, err
		}

		sdd_req := []byte{sel_cmd, 0x20}
		sdd_res, err := p.inCommRf(sdd_req)
		if err != nil {
			return nil, err
		}
		sdd_res = sdd_res[13 : 13+5]
		if _, err := p.inset_protocol(map[string]int{
			"add_crc":   1,
			"check_crc": 1,
		}); err != nil {
			return nil, err
		}

		sel_req := []byte{sel_cmd, 0x70}
		for _, b := range sdd_res {
			sel_req = append(sel_req, b)
		}
		sel_res, err := p.inCommRf(sel_req)
		if err != nil {
			return nil, err
		}
		sel_res = []byte{sel_res[13]}

		if sel_res[0]&0b00000100 != 0 {
			uid = append(uid, sdd_res[1:4]...)
		} else {
			uid = append(uid, sdd_res[0:4]...)
			break
		}
	}

	return uid, nil
}

func (p *packet) inCommRf(data []byte) ([]byte, error) {
	cmd := []byte{InCommRf, 0x36, 0x01}
	for _, d := range data {
		cmd = append(cmd, d)
	}

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

func (p *packet) inset_protocol(kwargs map[string]int) ([]byte, error) {
	data := inSetProtocol(kwargs)
	cmd := []byte{InSetProtocol}
	for _, d := range data {
		cmd = append(cmd, d)
	}

	return p.write(cmd)
}

type StatusError struct {
	Code int
}

func (e *StatusError) Error() string {
	return fmt.Sprintf("Status error: %d", e.Code)
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
