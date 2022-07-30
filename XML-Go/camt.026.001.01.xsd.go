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

// MissingOrIncorrectInformation ...
type MissingOrIncorrectInformation struct {
	MssngInf   []string `xml:"MssngInf"`
	IncrrctInf []string `xml:"IncrrctInf"`
}

// PaymentInstructionExtract ...
type PaymentInstructionExtract struct {
	AssgnrInstrId string             `xml:"AssgnrInstrId"`
	AssgneInstrId string             `xml:"AssgneInstrId"`
	CcyAmt        *CurrencyAndAmount `xml:"CcyAmt"`
	ValDt         string             `xml:"ValDt"`
}

// UnableToApplyIncorrectInfo1Code ...
type UnableToApplyIncorrectInfo1Code string

// UnableToApplyJustificationChoice ...
type UnableToApplyJustificationChoice struct {
	AnyInf            bool                           `xml:"AnyInf"`
	MssngOrIncrrctInf *MissingOrIncorrectInformation `xml:"MssngOrIncrrctInf"`
}

// UnableToApplyMissingInfo1Code ...
type UnableToApplyMissingInfo1Code string

// YesNoIndicator ...
type YesNoIndicator bool

// Camt02600101 ...
type Camt02600101 struct {
	XMLName xml.Name                          `xml:"camt.026.001.01"`
	Assgnmt *CaseAssignment                   `xml:"Assgnmt"`
	Case    *Case                             `xml:"Case"`
	Undrlyg *PaymentInstructionExtract        `xml:"Undrlyg"`
	Justfn  *UnableToApplyJustificationChoice `xml:"Justfn"`
}
