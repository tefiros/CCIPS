package i2nsf

import (
	"fmt"
	"os"
	"strings"
)

type TemplateType string

const (
	AddSAD     TemplateType = "addSAD"
	AddSPD     TemplateType = "addSPD"
	DelSAD     TemplateType = "delSAD"
	DelSPD     TemplateType = "delSPD"
	addSadJson TemplateType = "addSadJson"
	addSpdJson TemplateType = "addSpdJson"
	delSadJson TemplateType = "delSadJson"
	delSpdJson TemplateType = "delSpdJson"
)

// G2GTemplates map loaded when the controller is started, in order to set the g2g xml templates
var G2GTemplates map[TemplateType]string

// H2hTemplates map loaded when the controller is started, in order to set the g2g xml templates
var H2hTemplates map[TemplateType]string

func LoadTemplates(dirPath string) error {
	G2GTemplates = make(map[TemplateType]string)
	H2hTemplates = make(map[TemplateType]string)
	var err error
	// First load the g2g templates
	G2GTemplates[AddSAD], err = readTemplate(dirPath, "g2g/add_sad_g2g.xml")
	if err != nil {
		return err
	}
	G2GTemplates[AddSPD], err = readTemplate(dirPath, "g2g/add_spd_g2g.xml")
	if err != nil {
		return err
	}
	G2GTemplates[DelSAD], err = readTemplate(dirPath, "g2g/del_sad_g2g.xml")
	if err != nil {
		return err
	}
	G2GTemplates[DelSPD], err = readTemplate(dirPath, "g2g/del_spd_g2g.xml")
	if err != nil {
		return err
	}
	// Then load the h2h templates
	H2hTemplates[AddSAD], err = readTemplate(dirPath, "h2h/add_sad_h2h.xml")
	if err != nil {
		return err
	}
	H2hTemplates[AddSPD], err = readTemplate(dirPath, "h2h/add_spd_h2h.xml")
	if err != nil {
		return err
	}
	H2hTemplates[DelSAD], err = readTemplate(dirPath, "h2h/del_sad_h2h.xml")
	if err != nil {
		return err
	}
	H2hTemplates[DelSPD], err = readTemplate(dirPath, "h2h/del_spd_h2h.xml")
	if err != nil {
		return err
	}
	H2hTemplates[addSadJson], err = readTemplate(dirPath, "h2h/add_sad_h2h.json")
	if err != nil {
		return err
	}
	H2hTemplates[addSpdJson], err = readTemplate(dirPath, "h2h/add_spd_h2h.json")
	if err != nil {
		return err
	}
	H2hTemplates[delSadJson], err = readTemplate(dirPath, "h2h/del_sad_h2h.json")
	if err != nil {
		return err
	}
	H2hTemplates[delSpdJson], err = readTemplate(dirPath, "h2h/del_spd_h2h.json")
	if err != nil {
		return err
	}
	return nil
}

func readTemplate(dirPath string, file string) (string, error) {
	b, err := os.ReadFile(fmt.Sprintf("%s/%s", dirPath, file))
	return string(b), err
}

func replace(template string, replaceName string, val interface{}) (newT string) {
	switch val.(type) {
	case bool:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%t", val), -1)
	case string:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%s", val), -1)
	case int, int8, int16, int64, uint, uint8, uint16, uint64:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%d", val), -1)
	case []byte:
		{
			input := fmt.Sprintf("%x", val)
			chunks := make([]string, 0, len(input)/2)
			for i := 0; i < len(input); i += 2 {
				if i+2 > len(input) {
					chunks = append(chunks, input[i:])
				} else {
					chunks = append(chunks, input[i:i+2])
				}
			}
			// join the chunks with ":" separator
			output := strings.Join(chunks, ":")
			newT = strings.Replace(template, replaceName, fmt.Sprintf("%s", output), -1)
		}
	default:
		newT = strings.Replace(template, replaceName, fmt.Sprintf("%v", val), -1)
	}
	return newT
}

// formatG2GSADValues Return the XML configuration of a SAD entry based in the input
func formatG2GSADValues(config *IpsecConfig, localPrefix, remotePrefix, local, remote string) string {
	t := G2GTemplates[AddSAD]
	// NOTE: we need to separate the ID_NAME when adding new associations since if we dond do this
	// we cannot differentiate and sysrepo instead of creating will modify.
	t = replace(t, "ID_NAME", fmt.Sprintf("%s_%d", config.name, config.spi))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "ENC_KEY", config.cryptoConfig.encKey)
	t = replace(t, "ENC_IV", config.cryptoConfig.iv)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "INT_KEY", config.cryptoConfig.intKey)
	t = replace(t, "HARD_BYTES", config.hardLifetime.nBytes)
	t = replace(t, "HARD_PACKETS", config.hardLifetime.nPackets)
	t = replace(t, "HARD_TIME", config.hardLifetime.time)
	t = replace(t, "HARD_IDLE", config.hardLifetime.timeIdle)
	t = replace(t, "SOFT_BYTES", config.softLifetime.nBytes)
	t = replace(t, "SOFT_PACKETS", config.softLifetime.nPackets)
	t = replace(t, "SOFT_TIME", config.softLifetime.time)
	t = replace(t, "SOFT_IDLE", config.softLifetime.timeIdle)
	t = replace(t, "LOCAL_TUNNEL", local)
	t = replace(t, "REMOTE_TUNNEL", remote)
	t = replace(t, "SPI", config.spi)
	return t
}

// formatG2GSPDValues Return the XML configuration of a SAD entry based in the input
func formatG2GSPDValues(config *IpsecConfig, localPrefix, remotePrefix, local, remote, direction string) string {
	t := G2GTemplates[AddSPD]
	t = replace(t, "ID_NAME", fmt.Sprintf("%s", config.name))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "LOCAL_TUNNEL", local)
	t = replace(t, "REMOTE_TUNNEL", remote)
	t = replace(t, "DIRECTION", direction)
	t = replace(t, "ENC_KEY_LENGTH", config.cryptoConfig.encKeyLength)
	return t
}

// formatH2HSADValues Return the XML configuration of a SAD entry based in the input
func formatH2HSADValues(config *IpsecConfig, localPrefix, remotePrefix string) string {
	t := H2hTemplates[AddSAD]
	// NOTE: we need to separate the ID_NAME when adding new associations since if we dond do this
	// we cannot differentiate and sysrepo instead of creating will modify.
	t = replace(t, "ID_NAME", fmt.Sprintf("%s_%d", config.name, config.spi))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "ENC_KEY", config.cryptoConfig.encKey)
	t = replace(t, "ENC_IV", config.cryptoConfig.iv)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "INT_KEY", config.cryptoConfig.intKey)
	t = replace(t, "HARD_BYTES", config.hardLifetime.nBytes)
	t = replace(t, "HARD_PACKETS", config.hardLifetime.nPackets)
	t = replace(t, "HARD_TIME", config.hardLifetime.time)
	t = replace(t, "HARD_IDLE", config.hardLifetime.timeIdle)
	t = replace(t, "SOFT_BYTES", config.softLifetime.nBytes)
	t = replace(t, "SOFT_PACKETS", config.softLifetime.nPackets)
	t = replace(t, "SOFT_TIME", config.softLifetime.time)
	t = replace(t, "SOFT_IDLE", config.softLifetime.timeIdle)
	t = replace(t, "SPI", config.spi)
	return t
}

// formatH2HSADValues Return the JSON configuration of a SAD entry based in the input
func formatH2HSADValuesJson(config *IpsecConfig, localPrefix, remotePrefix string) string {
	t := H2hTemplates[addSadJson]
	// NOTE: we need to separate the ID_NAME when adding new associations since if we dond do this
	// we cannot differentiate and sysrepo instead of creating will modify.
	t = replace(t, "ID_NAME", fmt.Sprintf("%s_%d", config.name, config.spi))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "ENC_KEY", config.cryptoConfig.encKey)
	t = replace(t, "ENC_IV", config.cryptoConfig.iv)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "INT_KEY", config.cryptoConfig.intKey)
	t = replace(t, "HARD_BYTES", config.hardLifetime.nBytes)
	t = replace(t, "HARD_PACKETS", config.hardLifetime.nPackets)
	t = replace(t, "HARD_TIME", config.hardLifetime.time)
	t = replace(t, "HARD_IDLE", config.hardLifetime.timeIdle)
	t = replace(t, "SOFT_BYTES", config.softLifetime.nBytes)
	t = replace(t, "SOFT_PACKETS", config.softLifetime.nPackets)
	t = replace(t, "SOFT_TIME", config.softLifetime.time)
	t = replace(t, "SOFT_IDLE", config.softLifetime.timeIdle)
	t = replace(t, "SPI", config.spi)
	return t
}

// formatH2HSPDValues Return the XML configuration of a SAD entry based in the input
func formatH2HSPDValues(config *IpsecConfig, localPrefix, remotePrefix, direction string) string {
	t := H2hTemplates[AddSPD]
	t = replace(t, "ID_NAME", fmt.Sprintf("%s", config.name))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "DIRECTION", direction)
	t = replace(t, "ENC_KEY_LENGTH", config.cryptoConfig.encKeyLength)
	return t
}

// formatH2HSPDValues Return the JSON configuration of a SAD entry based in the input
func formatH2HSPDValuesJson(config *IpsecConfig, localPrefix, remotePrefix, direction string) string {
	t := H2hTemplates[addSpdJson]
	t = replace(t, "ID_NAME", fmt.Sprintf("%s", config.name))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace(t, "LOCAL_PREFIX", localPrefix)
	t = replace(t, "REMOTE_PREFIX", remotePrefix)
	t = replace(t, "ENC_ALG", config.cryptoConfig.encAlg)
	t = replace(t, "INT_ALG", config.cryptoConfig.intAlg)
	t = replace(t, "DIRECTION", direction)
	t = replace(t, "ENC_KEY_LENGTH", config.cryptoConfig.encKeyLength)
	return t
}

// formatDelSAD Return the XML configuration, so we can delete the SAD entry
func formatDelSAD(config *IpsecConfig) string {
	t := G2GTemplates[DelSAD]
	// NOTE: we need to separate the ID_NAME when adding new associations since if we dond do this
	// we cannot differentiate and sysrepo instead of creating will modify.
	t = replace(t, "ID_NAME", fmt.Sprintf("%s_%d", config.name, config.spi))
	t = replace(t, "REQ_ID", config.reqId)
	t = replace("<sad>DATA</sad>", "DATA", t)
	return replace(EditconfigTemplate, "REPLACE_DATA", t)
}

func formatDelSADJson(config *IpsecConfig) string {
	t := H2hTemplates[delSadJson]
	// NOTE: we need to separate the ID_NAME when adding new associations since if we dond do this
	// we cannot differentiate and sysrepo instead of creating will modify.
	t = replace(t, "ID_NAME", fmt.Sprintf("%s_%d", config.name, config.spi))
	t = replace(t, "REQ_ID", config.reqId)
	//t = replace("<sad>DATA</sad>", "DATA", t)
	return replace(EditconfigTemplate, "REPLACE_DATA", t)
}

// formatDelSPD Return the XML configuration, so we can delete the SPD entry
func formatDelSPD(config *IpsecConfig) string {
	t := G2GTemplates[DelSPD]
	t = replace(t, "ID_NAME", config.name)
	t = replace(t, "REQ_ID", config.reqId)
	t = replace("<spd>DATA</spd>", "DATA", t)
	return replace(EditconfigTemplate, "REPLACE_DATA", t)
}

func formatDelSPDJson(config *IpsecConfig) string {
	t := H2hTemplates[delSpdJson]
	t = replace(t, "ID_NAME", config.name)
	t = replace(t, "REQ_ID", config.reqId)
	//t = replace("<spd>DATA</spd>", "DATA", t)
	return replace(EditconfigTemplate, "REPLACE_DATA", t)
}

var EditconfigTemplate = "<ipsec-ikeless\n  xmlns=\"urn:ietf:params:xml:ns:yang:ietf-i2nsf-ikeless\"\n  xmlns:nc=\"urn:ietf:params:xml:ns:netconf:base:1.0\">\nREPLACE_DATA\n</ipsec-ikeless>"

var EditconfigTemplateJson = "REPLACE_DATA"

// GenerateI2NSFConfig generates the edit-config template
func GenerateI2NSFConfig(SADEntries, SPDEntries []string) string {
	var data string
	// First parse sad entries when len(SPDEntries) > 0
	if len(SPDEntries) > 0 {
		data = fmt.Sprintf("<spd>%s</spd>", strings.Join(SPDEntries, "\n"))
	}
	if len(SADEntries) > 0 {
		entries := fmt.Sprintf("<sad>\n%s\n</sad>", strings.Join(SADEntries, "\n"))
		if len(data) > 0 {
			data = fmt.Sprintf("%s%s", data, entries)
		} else {
			data = entries
		}
	}
	return replace(EditconfigTemplate, "REPLACE_DATA", data)
}

func GenerateI2NSFConfigJson(SADEntries, SPDEntries []string) string {
	var data string
	// First parse sad entries when len(SPDEntries) > 0
	if len(SPDEntries) > 0 {
		data = fmt.Sprintf("%s", strings.Join(SPDEntries, "\n"))
	}
	if len(SADEntries) > 0 {
		entries := fmt.Sprintf("\n%s\n", strings.Join(SADEntries, "\n"))
		if len(data) > 0 {
			data = fmt.Sprintf("%s%s", data, entries)
		} else {
			data = entries
		}
	}
	return replace(EditconfigTemplateJson, "REPLACE_DATA", data)
}
