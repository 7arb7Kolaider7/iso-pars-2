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

// ISODateTime ...
type ISODateTime string

// Max35Text ...
type Max35Text string

// YesNoIndicator ...
type YesNoIndicator bool

// Camt03200101 ...
type Camt03200101 struct {
	XMLName xml.Name        `xml:"camt.032.001.01"`
	Assgnmt *CaseAssignment `xml:"Assgnmt"`
	Case    *Case           `xml:"Case"`
}
