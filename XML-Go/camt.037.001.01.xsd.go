package schema

import (
	"encoding/xml"
)

// Document ...
type Document *Document

// AnyBICIdentifier ...
type AnyBICIdentifier string

// CancellationReason1Code ...
type CancellationReason1Code string

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

// DebitAuthorisationDetails ...
type DebitAuthorisationDetails struct {
	CxlRsn     string             `xml:"CxlRsn"`
	AmtToDbt   *CurrencyAndAmount `xml:"AmtToDbt"`
	ValDtToDbt string             `xml:"ValDtToDbt"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Max35Text ...
type Max35Text string

// PaymentInstructionExtract ...
type PaymentInstructionExtract struct {
	AssgnrInstrId string             `xml:"AssgnrInstrId"`
	AssgneInstrId string             `xml:"AssgneInstrId"`
	CcyAmt        *CurrencyAndAmount `xml:"CcyAmt"`
	ValDt         string             `xml:"ValDt"`
}

// YesNoIndicator ...
type YesNoIndicator bool

// Camt03700101 ...
type Camt03700101 struct {
	XMLName xml.Name                   `xml:"camt.037.001.01"`
	Assgnmt *CaseAssignment            `xml:"Assgnmt"`
	Case    *Case                      `xml:"Case"`
	Undrlyg *PaymentInstructionExtract `xml:"Undrlyg"`
	Dtl     *DebitAuthorisationDetails `xml:"Dtl"`
}
