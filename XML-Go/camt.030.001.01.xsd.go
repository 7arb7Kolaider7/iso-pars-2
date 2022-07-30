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

// CaseForwardingNotification ...
type CaseForwardingNotification struct {
	Justfn string `xml:"Justfn"`
}

// CaseForwardingNotification1Code ...
type CaseForwardingNotification1Code string

// ISODateTime ...
type ISODateTime string

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

// Camt03000101 ...
type Camt03000101 struct {
	XMLName xml.Name                    `xml:"camt.030.001.01"`
	Hdr     *ReportHeader               `xml:"Hdr"`
	Case    *Case                       `xml:"Case"`
	Assgnmt *CaseAssignment             `xml:"Assgnmt"`
	Ntfctn  *CaseForwardingNotification `xml:"Ntfctn"`
}
