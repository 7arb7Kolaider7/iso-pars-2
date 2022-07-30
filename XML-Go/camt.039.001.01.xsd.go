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

// CaseStatus ...
type CaseStatus struct {
	DtTm        string `xml:"DtTm"`
	CaseSts     string `xml:"CaseSts"`
	InvstgtnSts string `xml:"InvstgtnSts"`
	Rsn         string `xml:"Rsn"`
}

// CaseStatus1Code ...
type CaseStatus1Code string

// ISODateTime ...
type ISODateTime string

// InvestigationExecutionConfirmation1Code ...
type InvestigationExecutionConfirmation1Code string

// Max140Text ...
type Max140Text string

// Max35Text ...
type Max35Text string

// ReportHeader ...
type ReportHeader struct {
	Id      string `xml:"Id"`
	Fr      string `xml:"Fr"`
	To      string `xml:"To"`
	CreDtTm string `xml:"CreDtTm"`
}

// YesNoIndicator ...
type YesNoIndicator bool

// Camt03900101 ...
type Camt03900101 struct {
	XMLName    xml.Name        `xml:"camt.039.001.01"`
	Hdr        *ReportHeader   `xml:"Hdr"`
	Case       *Case           `xml:"Case"`
	Sts        *CaseStatus     `xml:"Sts"`
	NewAssgnmt *CaseAssignment `xml:"NewAssgnmt"`
}
