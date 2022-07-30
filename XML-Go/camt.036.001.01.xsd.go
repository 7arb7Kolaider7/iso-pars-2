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

// DebitAuthorisationConfirmation ...
type DebitAuthorisationConfirmation struct {
	DbtAuthstn bool               `xml:"DbtAuthstn"`
	AmtToDbt   *CurrencyAndAmount `xml:"AmtToDbt"`
	ValDtToDbt string             `xml:"ValDtToDbt"`
	Rsn        string             `xml:"Rsn"`
}

// ISODate ...
type ISODate string

// ISODateTime ...
type ISODateTime string

// Max140Text ...
type Max140Text string

// Max35Text ...
type Max35Text string

// YesNoIndicator ...
type YesNoIndicator bool

// Camt03600101 ...
type Camt03600101 struct {
	XMLName xml.Name                        `xml:"camt.036.001.01"`
	Assgnmt *CaseAssignment                 `xml:"Assgnmt"`
	Case    *Case                           `xml:"Case"`
	Conf    *DebitAuthorisationConfirmation `xml:"Conf"`
}
