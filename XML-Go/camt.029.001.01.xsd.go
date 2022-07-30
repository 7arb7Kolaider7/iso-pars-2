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

// InvestigationExecutionConfirmation1Code ...
type InvestigationExecutionConfirmation1Code string

// InvestigationStatusChoice ...
type InvestigationStatusChoice struct {
	Conf           string                             `xml:"Conf"`
	RjctdMod       []string                           `xml:"RjctdMod"`
	RjctdCxl       *RejectedCancellationJustification `xml:"RjctdCxl"`
	DplctOf        *Case                              `xml:"DplctOf"`
	AssgnmtCxlConf bool                               `xml:"AssgnmtCxlConf"`
}

// Max140Text ...
type Max140Text string

// Max35Text ...
type Max35Text string

// PaymentCancellationRejection1Code ...
type PaymentCancellationRejection1Code string

// PaymentInstructionExtract ...
type PaymentInstructionExtract struct {
	AssgnrInstrId string             `xml:"AssgnrInstrId"`
	AssgneInstrId string             `xml:"AssgneInstrId"`
	CcyAmt        *CurrencyAndAmount `xml:"CcyAmt"`
	ValDt         string             `xml:"ValDt"`
}

// PaymentModificationRejection1Code ...
type PaymentModificationRejection1Code string

// RejectedCancellationJustification ...
type RejectedCancellationJustification struct {
	RsnCd string `xml:"RsnCd"`
	Rsn   string `xml:"Rsn"`
}

// YesNoIndicator ...
type YesNoIndicator bool

// Camt02900101 ...
type Camt02900101 struct {
	XMLName   xml.Name                   `xml:"camt.029.001.01"`
	Assgnmt   *CaseAssignment            `xml:"Assgnmt"`
	RslvdCase *Case                      `xml:"RslvdCase"`
	Sts       *InvestigationStatusChoice `xml:"Sts"`
	CrrctnTx  *PaymentInstructionExtract `xml:"CrrctnTx"`
}
