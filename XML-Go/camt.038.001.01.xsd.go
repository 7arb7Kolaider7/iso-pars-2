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

// Camt03800101 ...
type Camt03800101 struct {
	XMLName xml.Name      `xml:"camt.038.001.01"`
	ReqHdr  *ReportHeader `xml:"ReqHdr"`
	Case    *Case         `xml:"Case"`
}
