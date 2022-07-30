package schema

import (
	"encoding/xml"
)

// Document ...
type Document *Document

// AnyBICIdentifier ...
type AnyBICIdentifier string

// Case ...
type Case struct {
	Id             string `xml:"Id"`
	Cretr          string `xml:"Cretr"`
	ReopCaseIndctn bool   `xml:"ReopCaseIndctn"`
}

// CaseAssignment ...
type CaseAssignment struct {
	Id      string `xml:"Id"`
	Assgnr  string `xml:"Assgnr"`
	Assgne  string `xml:"Assgne"`
	CreDtTm string `xml:"CreDtTm"`
}

// CurrencyAndAmountSimpleType ...
type CurrencyAndAmountSimpleType float64

// CurrencyAndAmount ...
type CurrencyAndAmount struct {
	CcyAttr string  `xml:"Ccy,attr"`
	Value   float64 `xml:",chardata"`
}

// CurrencyCode ...
type CurrencyCode string

// ISODateTime ...
type ISODateTime string

// Max35Text ...
type Max35Text string

// MissingCover ...
type MissingCover struct {
	MssngCoverIndctn bool `xml:"MssngCoverIndctn"`
}

// PaymentInstructionExtract ...
type PaymentInstructionExtract struct {
	AssgnrInstrId string             `xml:"AssgnrInstrId"`
	AssgneInstrId string             `xml:"AssgneInstrId"`
	CcyAmt        *CurrencyAndAmount `xml:"CcyAmt"`
	ValDt         string             `xml:"ValDt"`
}

// YesNoIndicator ...
type YesNoIndicator bool

// Camt02700101 ...
type Camt02700101 struct {
	XMLName    xml.Name                   `xml:"camt.027.001.01"`
	Assgnmt    *CaseAssignment            `xml:"Assgnmt"`
	Case       *Case                      `xml:"Case"`
	Undrlyg    *PaymentInstructionExtract `xml:"Undrlyg"`
	MssngCover *MissingCover              `xml:"MssngCover"`
}
